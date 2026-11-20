package app.openconnect.domains;

import org.junit.Test;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import static org.junit.Assert.*;
import static app.openconnect.domains.ServerPolicy.Action.*;
import static app.openconnect.domains.ServerPolicy.numeric;
import static app.openconnect.domains.DomainEngineTest.*;

public class ServerRouteEngineTest {
    private static final byte[] LOCAL = numeric("10.110.8.7"), REAL = numeric("203.0.113.8");
    private static void learn(ServerRouteEngine e, String name, byte[] ip, long time) {
        byte[] q = query(name, ip.length == 4 ? 1 : 28), r = response(q, ip);
        assertArrayEquals(r, e.dns(q, r, time));
    }
    @Test public void fullExcludeDnsAndPinnedConnections() {
        ServerRouteEngine e = new ServerRouteEngine(ServerPolicyTest.policy(null, "example.com", true, false, true));
        byte[] first = packet(LOCAL, REAL, 42000, 443, 6), second = packet(LOCAL, REAL, 42001, 443, 6);
        assertEquals(VPN, e.outgoing(first, 1000, false));
        learn(e, "www.example.com", REAL, 2000);
        assertEquals(VPN, e.outgoing(first, 2100, false)); assertEquals(DIRECT, e.outgoing(second, 2100, false));
        byte[] reply = packet(REAL, LOCAL, 443, 42001, 6);
        assertTrue(e.incoming(reply, DIRECT, 3000)); assertFalse(e.incoming(reply, VPN, 3000));
        // 60-second DNS TTL expiry must not move established TCP connections.
        assertEquals(DIRECT, e.outgoing(second, 100000, false));
        assertEquals(VPN, e.outgoing(packet(LOCAL, REAL, 42002, 443, 6), 100000, false));
    }
    @Test public void includeAndSharedIpPriorities() {
        ServerRouteEngine split = new ServerRouteEngine(ServerPolicyTest.policy("example.com", "excluded.test", false, true, false));
        assertEquals(DIRECT, split.address(REAL, 1000));
        learn(split, "example.com", REAL, 1000); assertEquals(VPN, split.address(REAL, 1001));
        learn(split, "excluded.test", REAL, 1100); assertEquals(DIRECT, split.address(REAL, 1200));
        ServerRouteEngine full = new ServerRouteEngine(ServerPolicyTest.policy("example.com", "excluded.test", true, true, false));
        learn(full, "excluded.test", REAL, 1000); learn(full, "example.com", REAL, 1100);
        assertEquals(VPN, full.address(REAL, 1200));
    }
    @Test public void udpLifetimeForcedResolverAndIpv6() {
        ServerRouteEngine e = new ServerRouteEngine(ServerPolicyTest.policy("example.com", null, false, true, true));
        byte[] p = packet(LOCAL, REAL, 40000, 53, 17);
        assertEquals(VPN, e.outgoing(p, 1000, true));
        assertTrue(e.incoming(packet(REAL, LOCAL, 53, 40000, 17), VPN, 2000));
        assertFalse(e.incoming(packet(REAL, LOCAL, 53, 40000, 17), VPN, 200001));
        assertEquals(DIRECT, e.outgoing(p, 200002, false));
        byte[] v6 = numeric("2001:db8::8"); learn(e, "example.com", v6, 200100);
        assertEquals(VPN, e.address(v6, 200101));
        byte[] fragment = packet(LOCAL, REAL, 1, 2, 17); Packets.put16(fragment, 6, 0x2000);
        assertEquals(DROP, e.outgoing(fragment, 200200, false));
    }
    @Test public void unrelatedDnsAndHttpsHints() {
        ServerRouteEngine e = new ServerRouteEngine(ServerPolicyTest.policy("example.com", null, false, false, false));
        learn(e, "other.test", REAL, 1000); assertEquals(DIRECT, e.address(REAL, 1001));
        byte[] q = query("example.com", 1), bad = response(q, REAL); bad[0] ^= 1;
        assertThrows(IllegalArgumentException.class, () -> e.dns(q, bad, 1000));
        byte[] https = query("example.com", 65); assertEquals(0, Packets.u16(e.dns(https, response(https, REAL), 1000), 6));
        byte[] aaaa = query("example.com", 28);
        assertEquals(0, Packets.u16(e.dns(aaaa, response(aaaa, numeric("2001:db8::8")), 1000), 6));
        assertEquals(DROP, e.address(numeric("2001:db8::8"), 1001));
    }
    @Test public void observesCorrelatedPlaintextDnsOnEitherPath() {
        for (boolean full : new boolean[] {false, true}) {
            ServerRouteEngine e = new ServerRouteEngine(ServerPolicyTest.policy(null, "example.com", full, false, true));
            byte[] resolver = numeric("9.9.9.9"), q = query("example.com", 1);
            byte[] incomingShape = packet(resolver, LOCAL, 53, 41000, 17);
            byte[] outbound = Packets.udpReply(Packets.parse(incomingShape), q);
            ServerPolicy.Action path = e.outgoing(outbound, 1000, false);
            byte[] answer = Packets.udpReply(Packets.parse(outbound), response(q, REAL));
            assertFalse(e.incoming(answer, path == VPN ? DIRECT : VPN, 1100));
            assertTrue(e.incoming(answer, path, 1200)); assertEquals(DIRECT, e.address(REAL, 1201));
        }
    }
    @Test public void freshSynReusesTupleWithCurrentDnsPolicy() {
        ServerRouteEngine e = new ServerRouteEngine(ServerPolicyTest.policy(null, "example.com", true, false, true));
        byte[] syn = packet(LOCAL, REAL, 41000, 443, 6); syn[33] = 2; syn[27] = 1;
        assertEquals(VPN, e.outgoing(syn, 1000, false));
        learn(e, "example.com", REAL, 1100);
        assertEquals(VPN, e.outgoing(syn, 1200, false)); // retransmission retains the initial path
        byte[] fresh = syn.clone(); fresh[27] = 2;
        assertEquals(DIRECT, e.outgoing(fresh, 1300, false));
    }

    @Test public void diagnosticsCanBeEnabledAndDisabledDuringConnection() {
        AtomicBoolean enabled = new AtomicBoolean();
        List<String> log = new ArrayList<>();
        ServerRouteEngine e = new ServerRouteEngine(ServerPolicyTest.policy(null, "example.com", true, false, true),
                new RouteDiagnostics(enabled::get, log::add));
        learn(e, "video.example.com", REAL, 1000);
        assertEquals(DIRECT, e.outgoing(packet(LOCAL, REAL, 40001, 443, 6), 1100, false));
        assertTrue(log.isEmpty());

        enabled.set(true);
        learn(e, "other.test", REAL, 1200);
        assertTrue(log.isEmpty());
        learn(e, "video.example.com", REAL, 1201);
        byte[] flow = packet(LOCAL, REAL, 40002, 443, 6);
        assertEquals(DIRECT, e.outgoing(flow, 1202, false));
        assertEquals(DIRECT, e.outgoing(flow, 1203, false));
        assertEquals(2, log.size());
        assertTrue(log.get(0).contains("video.example.com -> 203.0.113.8 policy=DIRECT ttl=60s"));
        assertTrue(log.get(1).contains("TCP [203.0.113.8]:443 -> DIRECT reason=dynamic_exclude"));

        enabled.set(false);
        assertEquals(DIRECT, e.outgoing(packet(LOCAL, REAL, 40003, 443, 6), 1204, false));
        assertEquals(2, log.size());
    }

    @Test public void routineFlowsCannotExhaustPolicyDiagnosticsBudget() {
        List<String> log = new ArrayList<>();
        ServerRouteEngine e = new ServerRouteEngine(ServerPolicyTest.policy("example.com", null, true, false, true),
                new RouteDiagnostics(() -> true, log::add));
        for (int i = 0; i < 40; i++) {
            assertEquals(VPN, e.outgoing(packet(LOCAL, REAL, 41000 + i, 443, 6), 1000 + i, false));
        }
        assertEquals(4, log.size());
        assertTrue(log.stream().allMatch(line -> line.contains("reason=full_tunnel_default")));

        byte[] excluded = numeric("192.0.2.8");
        learn(e, "www.example.com", excluded, 1100);
        assertEquals(DIRECT, e.outgoing(packet(LOCAL, excluded, 42000, 443, 17), 1200, false));
        assertTrue(log.get(4).contains("policy=VPN"));
        assertTrue(log.get(5).contains("UDP [192.0.2.8]:443 -> DIRECT reason=static_exclude"));
        assertEquals(VPN, e.outgoing(packet(LOCAL, REAL, 44000, 443, 6), 12000, false));
        assertEquals(7, log.size());
    }
}
