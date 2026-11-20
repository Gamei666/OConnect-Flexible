// SPDX-License-Identifier: GPL-2.0-or-later
package app.openconnect.domains;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.os.SystemClock;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructPollfd;
import android.util.AtomicFile;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/** One Android TUN and a datagram socketpair to OpenConnect. Server policies add
 * a userspace direct TCP/UDP path through explicitly protected uplink sockets. */
public final class DomainTunnel implements AutoCloseable {
    private final ParcelFileDescriptor tun, routerSide;
    private ParcelFileDescriptor nativeSide;
    private final DomainEngine engine;
    private final ServerPolicy serverPolicy;
    private final ServerRouteEngine serverEngine;
    private final DirectTunnel directTunnel;
    private final DomainRules rules;
    private final VpnService service;
    private final List<InetAddress> resolvers = new ArrayList<>();
    private final Set<java.io.Closeable> dnsSockets = Collections.newSetFromMap(new ConcurrentHashMap<>());
    private final ThreadPoolExecutor dnsWorkers = new ThreadPoolExecutor(4, 4, 0, TimeUnit.SECONDS, new ArrayBlockingQueue<>(64));
    private final AtomicFile state;
    private final Consumer<String> log;
    private final Runnable fatal;
    private final Object tunWrite = new Object(), vpnWrite = new Object();
    private volatile boolean stopped;
    private Thread outgoing, incoming;
    private int persistedCount;

    public DomainTunnel(VpnService service, ParcelFileDescriptor tun, DomainRules rules, boolean ipv6,
                        List<String> dns, File stateFile, Consumer<String> log, Runnable fatal) throws Exception {
        this(service, tun, rules, null, ipv6, null, null, dns, stateFile, log, fatal, null);
    }
    public DomainTunnel(VpnService service, ParcelFileDescriptor tun, ServerPolicy policy, String ipv4, String ipv6,
                        List<String> dns, File stateFile, Consumer<String> log, Runnable fatal,
                        BooleanSupplier diagnosticsEnabled) throws Exception {
        this(service, tun, null, policy, ipv6 != null, ipv4, ipv6, dns, stateFile, log, fatal, diagnosticsEnabled);
    }
    private DomainTunnel(VpnService service, ParcelFileDescriptor tun, DomainRules rules, ServerPolicy policy, boolean ipv6,
                         String local4, String local6,
                         List<String> dns, File stateFile, Consumer<String> log, Runnable fatal,
                         BooleanSupplier diagnosticsEnabled) throws Exception {
        this.tun = tun; this.log = log; this.fatal = fatal; this.rules = rules; this.service = service;
        this.serverPolicy = policy;
        serverEngine = policy == null ? null : new ServerRouteEngine(policy, new RouteDiagnostics(diagnosticsEnabled, log));
        state = policy == null ? new AtomicFile(stateFile) : null;
        List<String> saved = new ArrayList<>();
        if (state != null) try (BufferedReader reader = new BufferedReader(new InputStreamReader(state.openRead(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (saved.size() >= 4096 || line.length() > 600) throw new IOException("Invalid domain mapping file");
                saved.add(line);
            }
        } catch (java.io.FileNotFoundException ignored) { }
        engine = policy == null ? new DomainEngine(rules, ipv6, saved) : null;
        persistedCount = saved.size();
        for (String ip : dns) {
            // The initial implementation requires an IPv4 upstream DNS and IPv4 VPN address.
            if (ip.matches("[0-9.]+")) resolvers.add(InetAddress.getByName(ip));
        }
        if (resolvers.isEmpty()) throw new IOException("The VPN server must provide an IPv4 DNS resolver");
        FileDescriptor a = new FileDescriptor(), b = new FileDescriptor();
        Os.socketpair(OsConstants.AF_UNIX, OsConstants.SOCK_DGRAM, 0, a, b);
        try { nativeSide = ParcelFileDescriptor.dup(a); routerSide = ParcelFileDescriptor.dup(b); }
        catch (Exception e) {
            if (nativeSide != null) try { nativeSide.close(); } catch (IOException ignored) { }
            throw e;
        }
        finally { Os.close(a); Os.close(b); }
        DirectTunnel direct = null;
        try {
            if (policy != null) {
                direct = new DirectTunnel(service, stateFile.getParentFile(), local4,
                        local6 != null ? local6 : "fd42:6f63:6f6e:6e65::1",
                        packet -> {
                            if (!serverEngine.incoming(packet, ServerPolicy.Action.DIRECT, SystemClock.elapsedRealtime())) return;
                            try { write(packet, false); }
                            catch (Exception e) { if (!stopped) { log.accept("DIRECT delivery failed"); fatal.run(); } }
                        }, log, fatal);
            }
        } catch (Exception e) {
            routerSide.close(); if (nativeSide != null) nativeSide.close(); throw e;
        }
        directTunnel = direct;
    }

    /** Ownership transfers to libopenconnect, which closes it at mainloop shutdown. */
    public int detachNativeFd() { int fd = nativeSide.detachFd(); nativeSide = null; return fd; }

    public void start() {
        if (directTunnel != null) directTunnel.start();
        outgoing = new Thread(() -> pump(tun.getFileDescriptor(), true), "domain-tun-out");
        incoming = new Thread(() -> pump(routerSide.getFileDescriptor(), false), "domain-tun-in");
        outgoing.start(); incoming.start();
        log.accept(serverPolicy == null ? "DOMAIN: local domain rules enabled" :
                "DOMAIN: server policy active (include=" + serverPolicy.includeCount() + ", exclude=" + serverPolicy.excludeCount() + ", IPv4=" + (serverPolicy.full4 ? "full/exclude" : "split/include") + ")");
    }

    private void pump(FileDescriptor fd, boolean fromDevice) {
        byte[] buffer = new byte[65535];
        StructPollfd poll = new StructPollfd(); poll.fd = fd; poll.events = (short)OsConstants.POLLIN;
        try {
            while (!stopped) {
                int ready = Os.poll(new StructPollfd[] {poll}, 250);
                if (stopped) return;
                if (ready == 0) continue;
                if ((poll.revents & (OsConstants.POLLERR | OsConstants.POLLNVAL | OsConstants.POLLHUP)) != 0) {
                    throw new IOException("VPN packet channel closed");
                }
                int n = Os.read(fd, buffer, 0, buffer.length);
                if (n <= 0) throw new IOException("VPN packet channel EOF");
                byte[] packet = Arrays.copyOf(buffer, n);
                Packets.View view = Packets.parse(packet);
                if (view == null) continue;
                if (fromDevice && Arrays.equals(view.destination, Packets.DNS)) {
                    if (view.hasPorts() && view.protocol == 17 && view.destinationPort() == 53 &&
                            Packets.u16(packet, view.transport + 4) == n - view.transport) {
                        byte[] query = Arrays.copyOfRange(packet, view.transport + 8, n);
                        try { dnsWorkers.execute(() -> dns(view, query)); }
                        catch (java.util.concurrent.RejectedExecutionException e) { answer(view, DnsWire.error(query, 2)); }
                    }
                    continue;
                }
                // Real resolver traffic belongs to our own DNS workers, and needs no fake NAT.
                boolean resolver = false;
                byte[] address = fromDevice ? view.destination : view.source;
                for (InetAddress r : resolvers) if (Arrays.equals(address, r.getAddress())) { resolver = true; break; }
                if (serverEngine != null) {
                    long now = SystemClock.elapsedRealtime();
                    if (fromDevice) {
                        boolean vpnDns = resolver && view.hasPorts() && view.destinationPort() == 53;
                        ServerPolicy.Action path = serverEngine.outgoing(packet, now, vpnDns);
                        if (path == ServerPolicy.Action.VPN) write(packet, true);
                        else if (path == ServerPolicy.Action.DIRECT) directTunnel.send(packet);
                    } else if (serverEngine.incoming(packet, ServerPolicy.Action.VPN, now)) write(packet, false);
                    continue;
                }
                byte[] result;
                if (fromDevice) result = resolver ? packet : engine.toVpn(packet, SystemClock.elapsedRealtime());
                else {
                    // A selected website may share an IP with the VPN resolver.
                    // Match established NAT flows before ordinary resolver traffic.
                    result = engine.fromVpn(packet, SystemClock.elapsedRealtime());
                    if (result == null && resolver) result = packet;
                }
                if (result != null) write(result, fromDevice);
            }
        } catch (Exception e) {
            if (!stopped) { log.accept("DOMAIN packet channel failed: " + e.getMessage()); fatal.run(); }
        }
    }

    private void write(byte[] packet, boolean toVpn) throws Exception {
        synchronized (toVpn ? vpnWrite : tunWrite) {
            if (stopped) return;
            FileDescriptor fd = toVpn ? routerSide.getFileDescriptor() : tun.getFileDescriptor();
            int written = Os.write(fd, packet, 0, packet.length);
            if (written != packet.length) throw new IOException("Short packet write");
        }
    }

    private void answer(Packets.View query, byte[] response) {
        if (response == null || stopped) return;
        // The system uses UDP to our virtual DNS. Address responses are synthesized
        // small; unusually large non-address records fail explicitly rather than fragment.
        if (response.length > 1200) {
            byte[] q = Arrays.copyOfRange(query.data, query.transport + 8, query.length);
            response = DnsWire.error(q, 2);
        }
        if (response == null) return;
        try { write(Packets.udpReply(query, response), false); }
        catch (Exception e) { if (!stopped) { log.accept("DOMAIN DNS channel failed: " + e.getMessage()); fatal.run(); } }
    }

    private void dns(Packets.View packet, byte[] query) {
        try {
            if (query.length > 4096 || (query.length > 2 && (query[2] & 0x80) != 0)) throw new IOException("Invalid DNS query");
            DnsWire.Question question = DnsWire.question(query);
            byte[] response = resolve(query, serverPolicy != null ? !serverPolicy.gatewayHost(question.name) : rules.includes(question.name));
            if (serverEngine != null) response = serverEngine.dns(query, response, SystemClock.elapsedRealtime());
            else synchronized (engine) {
                response = engine.dns(query, response);
                if (persistedCount != engine.bindingCount()) {
                    persist(); // mapping must be durable before a fake address is returned
                    persistedCount = engine.bindingCount();
                }
            }
            answer(packet, response);
        } catch (Exception e) {
            if (!stopped) { log.accept("DOMAIN DNS: " + e.getMessage()); answer(packet, DnsWire.error(query, 2)); }
        }
    }

    private void persist() throws IOException {
        FileOutputStream out = null;
        try {
            out = state.startWrite();
            for (String line : engine.save()) out.write((line + "\n").getBytes(StandardCharsets.UTF_8));
            state.finishWrite(out);
        } catch (IOException e) {
            if (out != null) state.failWrite(out);
            throw e;
        }
    }

    public static Network uplink(VpnService service) throws IOException {
        ConnectivityManager manager = (ConnectivityManager)service.getSystemService(Context.CONNECTIVITY_SERVICE);
        Network fallback = null;
        for (Network network : manager.getAllNetworks()) {
            NetworkCapabilities c = manager.getNetworkCapabilities(network);
            if (c == null || c.hasTransport(NetworkCapabilities.TRANSPORT_VPN) || !c.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue;
            if (c.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) return network;
            fallback = network;
        }
        if (fallback == null) throw new IOException("No underlying network for direct DNS");
        return fallback;
    }

    private byte[] resolve(byte[] query, boolean selected) throws IOException {
        Network direct = selected ? null : uplink(service);
        List<InetAddress> servers = resolvers;
        if (direct != null) {
            ConnectivityManager manager = (ConnectivityManager)service.getSystemService(Context.CONNECTIVITY_SERVICE);
            LinkProperties link = manager.getLinkProperties(direct);
            if (link == null || link.getDnsServers().isEmpty()) throw new IOException("No DNS resolver on the underlying network");
            servers = link.getDnsServers();
        }
        IOException last = new IOException("No upstream DNS response");
        for (InetAddress server : servers) {
            if (stopped) throw new IOException("VPN stopped");
            try (DatagramSocket socket = new DatagramSocket()) {
                dnsSockets.add(socket);
                try {
                    if (direct != null) {
                        if (!service.protect(socket)) throw new IOException("Cannot protect direct DNS socket");
                        direct.bindSocket(socket);
                    }
                    socket.connect(server, 53); socket.setSoTimeout(2500);
                    socket.send(new DatagramPacket(query, query.length));
                    byte[] reply = new byte[65535];
                    DatagramPacket data = new DatagramPacket(reply, reply.length);
                    socket.receive(data);
                    byte[] result = Arrays.copyOf(reply, data.getLength());
                    if (result.length < 12 || Packets.u16(result, 0) != Packets.u16(query, 0)) throw new IOException("Invalid upstream DNS ID");
                    if ((result[2] & 2) != 0) result = tcpResolve(query, server, direct);
                    return result;
                } finally { dnsSockets.remove(socket); }
            } catch (IOException e) { last = e; }
        }
        throw last;
    }

    private byte[] tcpResolve(byte[] query, InetAddress server, Network direct) throws IOException {
        try (Socket socket = new Socket()) {
            dnsSockets.add(socket);
            try {
                if (direct != null) {
                    // Initialize the TCP file descriptor before Android tries to protect it.
                    socket.getReuseAddress();
                    if (!service.protect(socket)) throw new IOException("Cannot protect direct TCP DNS socket");
                    direct.bindSocket(socket);
                }
                socket.connect(new InetSocketAddress(server, 53), 2500); socket.setSoTimeout(3000);
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                out.writeShort(query.length); out.write(query); out.flush();
                DataInputStream in = new DataInputStream(socket.getInputStream());
                int n = in.readUnsignedShort();
                if (n < 12) throw new IOException("Short TCP DNS response");
                byte[] response = new byte[n]; in.readFully(response); return response;
            } finally { dnsSockets.remove(socket); }
        }
    }

    @Override public void close() {
        stopped = true;
        if (directTunnel != null) directTunnel.close();
        dnsWorkers.shutdownNow();
        for (java.io.Closeable socket : dnsSockets) try { socket.close(); } catch (IOException ignored) { }
        try { routerSide.close(); } catch (IOException ignored) { }
        try { tun.close(); } catch (IOException ignored) { }
        if (nativeSide != null) try { nativeSide.close(); } catch (IOException ignored) { }
        for (Thread thread : new Thread[] {outgoing, incoming}) if (thread != null && thread != Thread.currentThread()) {
            try { thread.join(1000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        }
    }
}
