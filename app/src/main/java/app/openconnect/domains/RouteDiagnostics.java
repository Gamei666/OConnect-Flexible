// SPDX-License-Identifier: GPL-2.0-or-later
package app.openconnect.domains;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Locale;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/** Rate-limited decision logs. Called under the routing engine's lock. */
final class RouteDiagnostics {
    private static final long WINDOW_MILLIS = 10_000;

    private enum Channel {
        DNS(20), POLICY_FLOW(24), BASE_FLOW(4);

        final int limit;

        Channel(int limit) {
            this.limit = limit;
        }
    }

    private final BooleanSupplier enabled;
    private final Consumer<String> log;
    private final int[] used = new int[Channel.values().length];
    private long windowStart;

    RouteDiagnostics(BooleanSupplier enabled, Consumer<String> log) {
        this.enabled = enabled;
        this.log = log;
    }

    private boolean allow(Channel channel, long now) {
        if (!enabled.getAsBoolean()) return false;
        if (now - windowStart >= WINDOW_MILLIS) {
            windowStart = now;
            Arrays.fill(used, 0);
        }
        int index = channel.ordinal();
        if (used[index] >= channel.limit) return false;
        used[index]++;
        return true;
    }

    void dns(String name, byte[] ip, ServerPolicy.Action action, long ttl, boolean proxied, long now) {
        if (allow(Channel.DNS, now)) {
            log.accept("SPLIT DNS: " + name + " -> " + ipAddress(ip) + " policy=" + action
                    + " ttl=" + ttl + "s source=" + (proxied ? "proxy" : "observed-udp"));
        }
    }

    void dnsResult(DnsWire.Question question, String result, boolean proxied, long now) {
        if (allow(Channel.DNS, now)) {
            log.accept("SPLIT DNS: " + question.name + " type=" + question.type
                    + " " + result + " source=" + (proxied ? "proxy" : "observed-udp"));
        }
    }

    void flow(Packets.View packet, ServerPolicy.Decision decision, long now) {
        boolean defaultPath = decision == ServerPolicy.Decision.FULL_TUNNEL_DEFAULT
                || decision == ServerPolicy.Decision.SPLIT_TUNNEL_DEFAULT
                || decision == ServerPolicy.Decision.VPN_DNS;
        if (allow(defaultPath ? Channel.BASE_FLOW : Channel.POLICY_FLOW, now)) {
            log.accept("SPLIT FLOW: " + (packet.protocol == 6 ? "TCP " : "UDP ")
                    + "[" + ipAddress(packet.destination) + "]:" + packet.destinationPort()
                    + " -> " + decision.action + " reason=" + decision.name().toLowerCase(Locale.ROOT));
        }
    }

    private static String ipAddress(byte[] address) {
        try {
            return InetAddress.getByAddress(address).getHostAddress();
        } catch (UnknownHostException invalidPacketAddress) {
            return Packets.hex(address);
        }
    }
}
