// SPDX-License-Identifier: GPL-2.0-or-later
package app.openconnect.domains;

import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructPollfd;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.function.Consumer;
import hev.htproxy.TProxyService;

/** A userspace TCP/UDP path to protected uplink sockets. Owns both socketpair FDs;
 * Hev explicitly borrows (does not close) its externally supplied TUN FD. */
public final class DirectTunnel implements AutoCloseable {
    private final ParcelFileDescriptor router, nativeFd;
    private final ProtectedSocksServer socks;
    private final File config;
    private final Consumer<byte[]> response;
    private final Consumer<String> log;
    private final Runnable fatal;
    private volatile boolean stopped;
    private boolean nativeStarted;
    private Thread reader;

    public DirectTunnel(VpnService service, File directory, String ipv4, String ipv6,
                        Consumer<byte[]> response, Consumer<String> log, Runnable fatal) throws Exception {
        this.response = response; this.log = log; this.fatal = fatal;
        if (ServerPolicy.numeric(ipv4).length != 4 || ServerPolicy.numeric(ipv6).length != 16) throw new IOException("Invalid interface addresses");
        socks = new ProtectedSocksServer(new ProtectedSocksServer.Protector() {
            @Override public void tcp(Socket socket, InetAddress destination) throws IOException {
                if (!service.protect(socket)) throw new IOException("Cannot protect direct TCP socket");
                if (!destination.isLoopbackAddress()) DomainTunnel.uplink(service).bindSocket(socket);
            }
            @Override public void udp(DatagramSocket socket) throws IOException {
                if (!service.protect(socket)) throw new IOException("Cannot protect direct UDP socket");
                DomainTunnel.uplink(service).bindSocket(socket);
            }
        }, log);
        ParcelFileDescriptor r = null, n = null;
        File cfg = null;
        try {
            FileDescriptor a = new FileDescriptor(), b = new FileDescriptor();
            Os.socketpair(OsConstants.AF_UNIX, OsConstants.SOCK_DGRAM, 0, a, b);
            try { r = ParcelFileDescriptor.dup(a); n = ParcelFileDescriptor.dup(b); }
            finally { Os.close(a); Os.close(b); }
            cfg = File.createTempFile("direct-tunnel-", ".yml", directory);
            String content = "tunnel:\n  name: domain-direct\n  mtu: 1280\n  ipv4: '" + ipv4 + "'\n  ipv6: '" + ipv6 + "'\n  icmp: 'off'\n" +
                    "socks5:\n  address: 127.0.0.1\n  port: " + socks.port() + "\n  udp: 'udp'\n  username: '" + socks.username + "'\n  password: '" + socks.password + "'\n" +
                    "misc:\n  max-session-count: 128\n  connect-timeout: 10000\n  tcp-read-write-timeout: 86400000\n  udp-read-write-timeout: 180000\n  log-level: error\n";
            try (FileOutputStream out = new FileOutputStream(cfg)) { out.write(content.getBytes(StandardCharsets.UTF_8)); }
            try {
                if (!TProxyService.TProxyStartService(cfg.getAbsolutePath(), n.getFd())) throw new IOException("Direct packet engine is already running or cannot start");
            } catch (LinkageError e) { throw new IOException("Cannot load the native direct packet engine", e); }
            nativeStarted = true;
        } catch (Exception e) {
            socks.close();
            if (r != null) try { r.close(); } catch (IOException ignored) { }
            if (n != null) try { n.close(); } catch (IOException ignored) { }
            if (cfg != null) cfg.delete();
            throw e;
        }
        router = r; nativeFd = n; config = cfg;
    }
    public void start() {
        reader = new Thread(() -> {
            byte[] buffer = new byte[65535]; StructPollfd poll = new StructPollfd();
            poll.fd = router.getFileDescriptor(); poll.events = (short)OsConstants.POLLIN;
            try {
                while (!stopped) {
                    int ready = Os.poll(new StructPollfd[] {poll}, 250);
                    if (stopped) return;
                    if (!TProxyService.TProxyIsRunning()) throw new IOException("Direct packet engine stopped");
                    if (ready == 0) continue;
                    if ((poll.revents & (OsConstants.POLLERR | OsConstants.POLLNVAL | OsConstants.POLLHUP)) != 0) throw new IOException("Direct packet channel closed");
                    int n = Os.read(router.getFileDescriptor(), buffer, 0, buffer.length);
                    if (n <= 0) throw new IOException("Direct packet channel EOF");
                    response.accept(Arrays.copyOf(buffer, n));
                }
            } catch (Exception e) { if (!stopped) { log.accept("DIRECT packet channel failed: " + e.getMessage()); fatal.run(); } }
        }, "domain-direct-in"); reader.start();
    }
    public synchronized void send(byte[] packet) throws Exception {
        if (stopped) return;
        if (Os.write(router.getFileDescriptor(), packet, 0, packet.length) != packet.length) throw new IOException("Short direct packet write");
    }
    @Override public void close() {
        stopped = true;
        if (nativeStarted) { TProxyService.TProxyStopService(); nativeStarted = false; }
        socks.close();
        try { router.close(); } catch (IOException ignored) { }
        try { nativeFd.close(); } catch (IOException ignored) { }
        config.delete();
        if (reader != null && reader != Thread.currentThread()) try { reader.join(1000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }
}
