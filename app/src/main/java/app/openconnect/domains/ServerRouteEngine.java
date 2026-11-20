// SPDX-License-Identifier: GPL-2.0-or-later
package app.openconnect.domains;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import static app.openconnect.domains.ServerPolicy.Action;
import static app.openconnect.domains.ServerPolicy.Decision;

/** DNS-derived IP policy and per-connection path pinning, without changing Android routes. */
public final class ServerRouteEngine {
    private static final int MAX_ADDRESSES = 16384, MAX_FLOWS = 8192;
    private static final class Lease { Action action; long until; }
    private static final class Flow { Action action; long seen, closeAt = Long.MAX_VALUE; boolean finOut, finIn; int synSequence; boolean synKnown; }
    private static final class PendingDns { byte[] query; long until; }
    private final ServerPolicy policy;
    private final RouteDiagnostics diagnostics;
    private final Map<String, Map<String, Lease>> addresses = new HashMap<>();
    private final Map<String, Flow> flows = new HashMap<>();
    private final Map<String, PendingDns> pendingDns = new HashMap<>();
    private long swept;
    public ServerRouteEngine(ServerPolicy policy) {
        this(policy, null);
    }

    ServerRouteEngine(ServerPolicy policy, RouteDiagnostics diagnostics) {
        this.policy = policy;
        this.diagnostics = diagnostics;
    }

    public synchronized byte[] dns(byte[] query, byte[] response, long now) {
        return dns(query, response, now, true);
    }

    private byte[] dns(byte[] query, byte[] response, long now, boolean proxied) {
        DnsWire.Question q = DnsWire.question(query);
        List<DnsWire.AddressAnswer> answer = DnsWire.addresses(query, response);
        if (!policy.hasDomainRule(q.name)) return response;
        // IP hints in HTTPS/SVCB could avoid subsequent observable A/AAAA lookups.
        // Let matching domains fall back to A/AAAA instead of using those hints.
        if (q.type == 64 || q.type == 65) {
            if (proxied && diagnostics != null) diagnostics.dnsResult(q, "filtered reason=address_hints", true, now);
            return proxied ? DnsWire.error(query, 0) : response;
        }
        sweep(now);
        for (DnsWire.AddressAnswer a : answer) {
            String key = Packets.hex(a.address);
            if (!addresses.containsKey(key) && addresses.size() >= MAX_ADDRESSES) throw new IllegalArgumentException("Dynamic address limit");
            Map<String, Lease> entries = addresses.computeIfAbsent(key, unused -> new HashMap<>());
            if (!entries.containsKey(q.name) && entries.size() >= 128) throw new IllegalArgumentException("Shared-address policy limit");
            Lease lease = new Lease(); lease.action = policy.domain(q.name, a.address.length);
            long ttl = Math.max(1, Math.min(a.ttl, 86400));
            lease.until = now + ttl * 1000;
            entries.put(q.name, lease);
            if (diagnostics != null) diagnostics.dns(q.name, a.address, lease.action, ttl, proxied, now);
        }
        if (answer.isEmpty() && (q.type == 1 || q.type == 28) && diagnostics != null) {
            diagnostics.dnsResult(q, "no_addresses rcode=" + (response[3] & 15), proxied, now);
        }
        // Learn even suppressed AAAA, so observed hardcoded UDP DNS cannot send
        // an include destination over a family the VPN does not provide.
        if (proxied && q.type == 28 && !policy.ipv6 && policy.domain(q.name, 16) == Action.VPN) {
            if (diagnostics != null) diagnostics.dnsResult(q, "filtered reason=no_ipv6_vpn", true, now);
            return DnsWire.error(query, 0);
        }
        return response;
    }
    private void sweep(long now) {
        if (now - swept < 1000) return;
        swept = now;
        Iterator<Map<String, Lease>> it = addresses.values().iterator();
        while (it.hasNext()) {
            Map<String, Lease> entries = it.next(); entries.values().removeIf(l -> l.until <= now);
            if (entries.isEmpty()) it.remove();
        }
        flows.values().removeIf(f -> f.closeAt <= now || now - f.seen > 86400000);
        pendingDns.values().removeIf(q -> q.until <= now);
    }
    public synchronized Action address(byte[] ip, long now) {
        return decision(ip, now).action;
    }

    private Decision decision(byte[] ip, long now) {
        boolean in = false, out = false;
        Map<String, Lease> entries = addresses.get(Packets.hex(ip));
        if (entries != null) for (Lease lease : entries.values()) if (lease.until > now) {
            in |= lease.action == Action.VPN; out |= lease.action == Action.DIRECT;
        }
        return policy.decide(ip, policy.combine(in, out, ip.length));
    }
    private static String key(Packets.View p, boolean response) {
        byte[] local = response ? p.destination : p.source, remote = response ? p.source : p.destination;
        int lp = response ? p.destinationPort() : p.sourcePort(), rp = response ? p.sourcePort() : p.destinationPort();
        return p.protocol + ":" + Packets.hex(local) + ":" + lp + ":" + Packets.hex(remote) + ":" + rp;
    }
    private static void touch(Flow f, Packets.View p, boolean incoming, long now) {
        f.seen = now;
        if (p.protocol == 17) f.closeAt = now + 180000;
        else if (p.protocol == 6) {
            int flags = p.data[p.transport + 13] & 255;
            if ((flags & 4) != 0) f.closeAt = now + 30000;
            if ((flags & 1) != 0) { if (incoming) f.finIn = true; else f.finOut = true; }
            if (f.finIn && f.finOut) f.closeAt = Math.min(f.closeAt, now + 120000);
        }
    }
    private void query(Packets.View p, long now) {
        if (p.protocol != 17 || p.destinationPort() != 53 || p.length - p.transport > 4104) return;
        byte[] bytes = Arrays.copyOfRange(p.data, p.transport + 8, p.length);
        try {
            DnsWire.Question q = DnsWire.question(bytes);
            if ((bytes[2] & 0x80) != 0 || !policy.hasDomainRule(q.name)) return;
            String key = key(p, false) + ":" + q.id;
            if (!pendingDns.containsKey(key) && pendingDns.size() >= 256) return;
            PendingDns pending = new PendingDns(); pending.query = bytes; pending.until = now + 10000;
            pendingDns.put(key, pending);
        } catch (IllegalArgumentException ignored) { }
    }
    private void answer(Packets.View p, long now) {
        if (p.protocol != 17 || p.sourcePort() != 53 || p.length - p.transport < 20) return;
        int id = Packets.u16(p.data, p.transport + 8);
        PendingDns pending = pendingDns.remove(key(p, true) + ":" + id);
        if (pending == null || pending.until <= now) return;
        try { dns(pending.query, Arrays.copyOfRange(p.data, p.transport + 8, p.length), now, false); }
        catch (IllegalArgumentException ignored) { /* never learn uncorrelated DNS */ }
    }
    public synchronized Action outgoing(byte[] packet, long now, boolean vpnDns) {
        sweep(now);
        Packets.View p = Packets.parse(packet);
        if (p == null) return Action.DROP;
        if (!p.hasPorts()) return p.fragment ? Action.DROP : address(p.destination, now);
        String key = key(p, false); Flow flow = flows.get(key);
        boolean syn = p.protocol == 6 && (p.data[p.transport + 13] & 0x12) == 2;
        int sequence = syn ? (Packets.u16(p.data, p.transport + 4) << 16) | Packets.u16(p.data, p.transport + 6) : 0;
        if (flow != null && (flow.closeAt <= now || (syn && (flow.finOut || flow.finIn ||
                !flow.synKnown || flow.synSequence != sequence)))) { flows.remove(key); flow = null; }
        if (flow == null) {
            if (flows.size() >= MAX_FLOWS) {
                if (diagnostics != null) diagnostics.flow(p, Decision.FLOW_LIMIT, now);
                return Action.DROP;
            }
            Decision decision = vpnDns ? Decision.VPN_DNS : decision(p.destination, now);
            flow = new Flow(); flow.action = decision.action;
            flows.put(key, flow);
            if (syn) { flow.synKnown = true; flow.synSequence = sequence; }
            if (diagnostics != null) diagnostics.flow(p, decision, now);
        }
        touch(flow, p, false, now);
        if (flow.action == Action.VPN || flow.action == Action.DIRECT) query(p, now);
        return flow.action;
    }
    public synchronized boolean incoming(byte[] packet, Action path, long now) {
        Packets.View p = Packets.parse(packet);
        if (p == null) return false;
        if (!p.hasPorts()) return path == Action.VPN; // authenticated VPN ICMP/fragment delivery
        Flow f = flows.get(key(p, true));
        if (f == null || f.action != path || f.closeAt <= now) return false;
        touch(f, p, true, now); answer(p, now); return true;
    }
}
