// SPDX-License-Identifier: GPL-2.0-or-later
package app.openconnect.domains;

import java.io.Closeable;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/** Loopback-only authenticated SOCKS endpoint for tun2socks. Every uplink socket
 * is explicitly protected and bound by the Android adapter before connecting. */
public final class ProtectedSocksServer implements AutoCloseable {
    public interface Protector {
        void tcp(Socket socket, InetAddress destination) throws IOException;
        void udp(DatagramSocket socket) throws IOException;
    }
    private final Protector protector;
    private final Consumer<String> log;
    private final ServerSocket listener;
    private final Semaphore capacity = new Semaphore(64);
    private final Set<Closeable> sockets = Collections.newSetFromMap(new ConcurrentHashMap<>());
    private final ThreadPoolExecutor tasks = new ThreadPoolExecutor(0, 192, 30, TimeUnit.SECONDS, new SynchronousQueue<>());
    private final Thread acceptor;
    private volatile boolean stopped;
    public final String username = "domainconnect", password;

    public ProtectedSocksServer(Protector protector, Consumer<String> log) throws IOException {
        this.protector = protector; this.log = log;
        byte[] secret = new byte[24]; new SecureRandom().nextBytes(secret); password = Packets.hex(secret);
        listener = new ServerSocket(0, 64, InetAddress.getByName("127.0.0.1"));
        listener.setSoTimeout(1000);
        acceptor = new Thread(this::accept, "domain-direct-socks"); acceptor.start();
    }
    public int port() { return listener.getLocalPort(); }
    private void accept() {
        while (!stopped) try {
            Socket client = listener.accept();
            if (!capacity.tryAcquire()) { client.close(); continue; }
            sockets.add(client);
            try { tasks.execute(() -> handle(client)); }
            catch (RuntimeException e) { sockets.remove(client); client.close(); capacity.release(); }
        } catch (SocketTimeoutException ignored) { }
        catch (IOException e) { if (!stopped) log.accept("DIRECT accept failed: " + e.getMessage()); }
    }
    private boolean authenticate(DataInputStream in, DataOutputStream out) throws IOException {
        if (in.readUnsignedByte() != 5) return false;
        int n = in.readUnsignedByte(); boolean supported = false;
        for (int i = 0; i < n; i++) supported |= in.readUnsignedByte() == 2;
        out.write(new byte[] {5, (byte)(supported ? 2 : 255)}); out.flush();
        if (!supported || in.readUnsignedByte() != 1) return false;
        byte[] user = new byte[in.readUnsignedByte()]; in.readFully(user);
        byte[] pass = new byte[in.readUnsignedByte()]; in.readFully(pass);
        boolean valid = MessageDigest.isEqual(user, username.getBytes(StandardCharsets.US_ASCII)) &
                MessageDigest.isEqual(pass, password.getBytes(StandardCharsets.US_ASCII));
        out.write(new byte[] {1, (byte)(valid ? 0 : 1)}); out.flush(); return valid;
    }
    private static void reply(DataOutputStream out, int code, InetAddress address, int port) throws IOException {
        out.write(new byte[] {5, (byte)code, 0}); SocksWire.writeTarget(out, address, port); out.flush();
    }
    private static void copy(InputStream in, OutputStream out) throws IOException {
        byte[] buf = new byte[16384]; int n;
        while ((n = in.read(buf)) >= 0) { if (n == 0) continue; out.write(buf, 0, n); out.flush(); }
    }
    private void handle(Socket client) {
        try {
            client.setSoTimeout(15000);
            DataInputStream in = new DataInputStream(client.getInputStream());
            DataOutputStream out = new DataOutputStream(client.getOutputStream());
            if (!authenticate(in, out)) return;
            if (in.readUnsignedByte() != 5) return;
            int command = in.readUnsignedByte();
            if (in.readUnsignedByte() != 0) return;
            SocksWire.Target target = SocksWire.readTarget(in);
            client.setSoTimeout(0);
            if (command == 1 && target.port != 0) tcp(client, in, out, target);
            else if (command == 3) udp(in, out);
            else reply(out, 7, InetAddress.getByName("127.0.0.1"), 0);
        } catch (Exception e) {
            if (!stopped && !(e instanceof java.io.EOFException)) log.accept("DIRECT session: " + e.getClass().getSimpleName());
        } finally {
            sockets.remove(client); try { client.close(); } catch (IOException ignored) { } capacity.release();
        }
    }
    private void tcp(Socket client, DataInputStream in, DataOutputStream out, SocksWire.Target target) throws Exception {
        try (Socket remote = new Socket()) {
            sockets.add(remote);
            Future<?> receive = null;
            try {
                // Android creates the socket's file descriptor on the first
                // socket option call. The protector needs it before connect.
                remote.setTcpNoDelay(true);
                protector.tcp(remote, target.address);
                try { remote.connect(new InetSocketAddress(target.address, target.port), 10000); }
                catch (IOException e) {
                    if (!stopped) log.accept("DIRECT TCP connect failed: " + e.getClass().getSimpleName());
                    reply(out, 5, InetAddress.getByName("127.0.0.1"), 0);
                    return;
                }
                client.setTcpNoDelay(true);
                reply(out, 0, remote.getLocalAddress(), remote.getLocalPort());
                receive = tasks.submit(() -> {
                    try { copy(remote.getInputStream(), out); }
                    catch (IOException ignored) { }
                    finally { try { client.shutdownOutput(); } catch (IOException ignored) { } }
                });
                copy(in, remote.getOutputStream()); remote.shutdownOutput(); receive.get();
            } finally {
                sockets.remove(remote);
                if (receive != null) receive.cancel(true);
            }
        }
    }
    private void udp(DataInputStream control, DataOutputStream out) throws Exception {
        try (DatagramSocket relay = new DatagramSocket(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0));
             DatagramSocket remote = new DatagramSocket()) {
            sockets.add(relay); sockets.add(remote);
            Future<?> send = null, receive = null;
            try {
                protector.udp(remote); relay.setSoTimeout(1000); remote.setSoTimeout(1000);
                reply(out, 0, InetAddress.getByName("127.0.0.1"), relay.getLocalPort());
                final InetSocketAddress[] endpoint = {null};
                Set<String> peers = Collections.synchronizedSet(new HashSet<>());
                send = tasks.submit(() -> {
                    byte[] buffer = new byte[65535];
                    while (!stopped && !relay.isClosed()) try {
                        DatagramPacket packet = new DatagramPacket(buffer, buffer.length); relay.receive(packet);
                        InetSocketAddress source = (InetSocketAddress)packet.getSocketAddress();
                        if (!source.getAddress().isLoopbackAddress()) continue;
                        synchronized (endpoint) { if (endpoint[0] == null) endpoint[0] = source; if (!endpoint[0].equals(source)) continue; }
                        SocksWire.Target target = SocksWire.datagram(buffer, packet.getLength());
                        if (target.payload.length > 65507 || (peers.size() >= 512 && !peers.contains(target.key()))) continue;
                        peers.add(target.key()); remote.send(new DatagramPacket(target.payload, target.payload.length, target.address, target.port));
                    } catch (SocketTimeoutException ignored) { }
                    catch (IOException e) { if (relay.isClosed() || remote.isClosed()) return; }
                });
                receive = tasks.submit(() -> {
                    byte[] buffer = new byte[65535];
                    while (!stopped && !remote.isClosed()) try {
                        DatagramPacket packet = new DatagramPacket(buffer, buffer.length); remote.receive(packet);
                        String key = Packets.hex(packet.getAddress().getAddress()) + ":" + packet.getPort();
                        if (!peers.contains(key)) continue;
                        InetSocketAddress target;
                        synchronized (endpoint) { target = endpoint[0]; }
                        if (target == null) continue;
                        byte[] frame = SocksWire.datagram(packet.getAddress(), packet.getPort(), buffer, packet.getLength());
                        if (frame.length <= 65507) relay.send(new DatagramPacket(frame, frame.length, target));
                    } catch (SocketTimeoutException ignored) { }
                    catch (IOException e) { if (relay.isClosed() || remote.isClosed()) return; }
                });
                while (!stopped && control.read() >= 0) { /* TCP control lifetime owns the UDP association. */ }
            } finally {
                sockets.remove(relay); sockets.remove(remote);
                if (send != null) send.cancel(true); if (receive != null) receive.cancel(true);
            }
        }
    }
    @Override public void close() {
        stopped = true;
        try { listener.close(); } catch (IOException ignored) { }
        for (Closeable socket : sockets) try { socket.close(); } catch (IOException ignored) { }
        tasks.shutdownNow();
        if (acceptor != Thread.currentThread()) try { acceptor.join(1500); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }
}
