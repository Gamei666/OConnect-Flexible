// SPDX-License-Identifier: GPL-2.0-or-later
package app.openconnect.domains;

import org.junit.Test;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import static org.junit.Assert.*;

public class DomainEngineTest {
    private static final byte[] REAL4 = {(byte)203, 0, 113, 8};
    private static final byte[] LOCAL4 = {10, 0, 0, 7};
    private static final byte[] REAL6 = Packets.unhex("20010db8000000000000000000000008");
    private static final byte[] LOCAL6 = Packets.unhex("20010db8000100000000000000000007");
    private static DomainEngine engine(boolean ipv6) {
        return new DomainEngine(new DomainRules("example.com", "video.example.com"), ipv6, Collections.emptyList());
    }
    static byte[] encodedName(String name) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (String label : name.split("\\.")) {
            byte[] b = label.getBytes(StandardCharsets.US_ASCII); out.write(b.length); out.write(b, 0, b.length);
        }
        out.write(0); return out.toByteArray();
    }
    static byte[] query(String name, int type) {
        byte[] labels = encodedName(name), p = new byte[12 + labels.length + 4];
        Packets.put16(p, 0, 1234); p[2] = 1; Packets.put16(p, 4, 1);
        System.arraycopy(labels, 0, p, 12, labels.length);
        Packets.put16(p, p.length - 4, type); Packets.put16(p, p.length - 2, 1);
        return p;
    }
    static byte[] response(byte[] query, byte[] real) {
        byte[] p = Arrays.copyOf(query, query.length + 12 + real.length);
        p[2] = (byte)0x81; p[3] = (byte)0xa0; Packets.put16(p, 6, 1);
        int at = query.length;
        p[at] = (byte)0xc0; p[at + 1] = 12;
        Packets.put16(p, at + 2, real.length == 4 ? 1 : 28); Packets.put16(p, at + 4, 1);
        Packets.put16(p, at + 8, 60); Packets.put16(p, at + 10, real.length);
        System.arraycopy(real, 0, p, at + 12, real.length); return p;
    }
    private static byte[] address(byte[] answer) {
        return Arrays.copyOfRange(answer, answer.length - (Packets.u16(answer, DnsWire.question(answer).end + 2) == 1 ? 4 : 16), answer.length);
    }
    private static byte[] learn(DomainEngine e, String name, byte[] real) {
        byte[] q = query(name, real.length == 4 ? 1 : 28);
        return address(e.dns(q, response(q, real)));
    }
    static byte[] packet(byte[] source, byte[] dest, int sourcePort, int destPort, int protocol) {
        int h = source.length == 4 ? 20 : 40, transport = protocol == 6 ? 20 : 8;
        byte[] p = new byte[h + transport + 5];
        if (h == 20) {
            p[0] = 0x45; p[8] = 64; p[9] = (byte)protocol; Packets.put16(p, 2, p.length);
            System.arraycopy(source, 0, p, 12, 4); System.arraycopy(dest, 0, p, 16, 4);
            Packets.put16(p, 10, (~Packets.sum(p, 0, 20, 0)) & 65535);
        } else {
            p[0] = 0x60; p[6] = (byte)protocol; p[7] = 64; Packets.put16(p, 4, p.length - 40);
            System.arraycopy(source, 0, p, 8, 16); System.arraycopy(dest, 0, p, 24, 16);
        }
        Packets.put16(p, h, sourcePort); Packets.put16(p, h + 2, destPort);
        if (protocol == 6) { p[h + 12] = 0x50; p[h + 13] = 0x10; }
        else Packets.put16(p, h + 4, p.length - h);
        for (int i = 0; i < 5; i++) p[h + transport + i] = (byte)(i + 1);
        int checksum = (~Packets.sum(p, h, p.length,
                Packets.sum(p, h == 20 ? 12 : 8, h == 20 ? 20 : 40, protocol + p.length - h))) & 65535;
        Packets.put16(p, h + (protocol == 6 ? 16 : 6), checksum == 0 && protocol == 17 ? 65535 : checksum);
        return p;
    }
    private static void checksums(byte[] packet) {
        Packets.View p = Packets.parse(packet); assertNotNull(p);
        if (p.version == 4) assertEquals(65535, Packets.sum(packet, 0, (packet[0] & 15) * 4, 0));
        assertEquals(65535, Packets.sum(packet, p.transport, p.length,
                Packets.sum(packet, p.version == 4 ? 12 : 8, p.version == 4 ? 20 : 40, p.protocol + p.length - p.transport)));
    }

    @Test public void suffixRules() {
        DomainRules r = new DomainRules("example.com; *.internal.example.com", "example.com, video.internal.example.com");
        assertFalse(r.includes("example.com")); assertTrue(r.includes("WWW.INTERNAL.EXAMPLE.COM."));
        assertFalse(r.includes("video.internal.example.com")); assertFalse(r.includes("badexample.com"));
        assertThrows(IllegalArgumentException.class, () -> new DomainRules("https://example.com/", ""));
        assertThrows(IllegalArgumentException.class, () -> new DomainRules("", "example.com"));
        assertTrue(new DomainRules("пример.рф", "").includes("xn--e1afmkfd.xn--p1ai"));
        r = new DomainRules("example.com", ""); r.bypassHost("vpn.example.com");
        assertFalse(r.includes("vpn.example.com")); assertTrue(r.includes("www.example.com"));
    }
    @Test public void includeExcludeAndDnssec() {
        DomainEngine e = engine(true);
        byte[] q = query("www.example.com", 1), a = e.dns(q, response(q, REAL4));
        assertTrue(Packets.fake(address(a))); assertEquals(0, a[3] & 0x20);
        q = query("video.example.com", 1); byte[] direct = response(q, REAL4);
        assertArrayEquals(direct, e.dns(q, direct));
        q = query("other.test", 1); direct = response(q, REAL4);
        assertArrayEquals(direct, e.dns(q, direct));
        q = query("example.com", 65); direct = response(q, REAL4);
        assertEquals(0, Packets.u16(e.dns(q, direct), 6));
    }
    @Test public void nativeIpv6OrSuppression() {
        DomainEngine e = engine(false);
        byte[] q = query("example.com", 28);
        assertEquals(0, Packets.u16(e.dns(q, response(q, REAL6)), 6));
        assertEquals(0, e.bindingCount());
        e = engine(true);
        assertTrue(Packets.fake(learn(e, "example.com", REAL6)));
    }
    @Test public void natRoundTripAllTransports() {
        for (boolean v6 : new boolean[] {false, true}) for (int protocol : new int[] {6, 17}) {
            DomainEngine e = engine(true);
            byte[] real = v6 ? REAL6 : REAL4, local = v6 ? LOCAL6 : LOCAL4;
            byte[] fake = learn(e, "example.com", real);
            byte[] sent = e.toVpn(packet(local, fake, 42000, 443, protocol), 1000);
            assertArrayEquals(real, Packets.parse(sent).destination); checksums(sent);
            int port = Packets.parse(sent).sourcePort();
            byte[] returned = e.fromVpn(packet(real, local, 443, port, protocol), 2000);
            assertArrayEquals(fake, Packets.parse(returned).source);
            assertEquals(42000, Packets.parse(returned).destinationPort()); checksums(returned);
        }
    }
    @Test public void sharedCdnAndPortCollision() {
        DomainEngine e = engine(true);
        byte[] a = learn(e, "a.example.com", REAL4), b = learn(e, "b.example.com", REAL4);
        assertFalse(Arrays.equals(a, b));
        byte[] first = e.toVpn(packet(LOCAL4, a, 42000, 443, 6), 1000);
        byte[] second = e.toVpn(packet(LOCAL4, b, 42000, 443, 6), 1000);
        int ap = Packets.parse(first).sourcePort(), bp = Packets.parse(second).sourcePort();
        assertNotEquals(ap, bp); checksums(first); checksums(second);
        assertArrayEquals(a, Packets.parse(e.fromVpn(packet(REAL4, LOCAL4, 443, ap, 6), 2000)).source);
        assertArrayEquals(b, Packets.parse(e.fromVpn(packet(REAL4, LOCAL4, 443, bp, 6), 2000)).source);
    }
    @Test public void persistenceAndFlowLifetime() {
        DomainEngine e = engine(true);
        byte[] a = learn(e, "a.example.com", REAL4), a6 = learn(e, "a.example.com", REAL6);
        DomainEngine restored = new DomainEngine(new DomainRules("example.com", ""), true, e.save());
        assertArrayEquals(a, learn(restored, "a.example.com", REAL4));
        assertArrayEquals(a6, learn(restored, "a.example.com", REAL6));
        assertFalse(Arrays.equals(a, learn(restored, "b.example.com", REAL4)));
        byte[] sent = restored.toVpn(packet(LOCAL4, a, 42000, 443, 6), 1000);
        // DNS TTL is 60 seconds. TCP still maps correctly ten minutes later.
        byte[] reply = restored.fromVpn(packet(REAL4, LOCAL4, 443, Packets.parse(sent).sourcePort(), 6), 600000);
        assertNotNull(reply); checksums(reply);
    }
    @Test public void cnameAndMalformedResponses() {
        DomainEngine e = engine(true);
        byte[] q = query("example.com", 1), target = encodedName("cdn.other.test");
        byte[] p = Arrays.copyOf(q, q.length + 12 + target.length + target.length + 10 + 4);
        p[2] = (byte)0x81; p[3] = (byte)0x80; Packets.put16(p, 6, 2);
        int at = q.length; p[at] = (byte)0xc0; p[at + 1] = 12;
        Packets.put16(p, at + 2, 5); Packets.put16(p, at + 4, 1); Packets.put16(p, at + 8, 30);
        Packets.put16(p, at + 10, target.length); System.arraycopy(target, 0, p, at + 12, target.length);
        at += 12 + target.length; System.arraycopy(target, 0, p, at, target.length); at += target.length;
        Packets.put16(p, at, 1); Packets.put16(p, at + 2, 1); Packets.put16(p, at + 6, 60); Packets.put16(p, at + 8, 4);
        System.arraycopy(REAL4, 0, p, at + 10, 4);
        assertTrue(Packets.fake(address(e.dns(q, p))));
        byte[] bad = p.clone(); bad[0] ^= 1;
        assertThrows(IllegalArgumentException.class, () -> e.dns(q, bad));
        byte[] cycle = p.clone(); cycle[12] = (byte)0xc0; cycle[13] = 12;
        assertThrows(IllegalArgumentException.class, () -> e.dns(q, cycle));
        byte[] shortRecord = Arrays.copyOf(p, p.length - 1);
        assertThrows(IllegalArgumentException.class, () -> e.dns(q, shortRecord));
    }
    @Test public void udpReplyAndFailClosed() {
        DomainEngine e = engine(true);
        byte[] q = query("example.com", 1);
        byte[] request = packet(LOCAL4, Packets.DNS, 42000, 53, 17);
        byte[] reply = Packets.udpReply(Packets.parse(request), DnsWire.error(q, 2));
        checksums(reply); assertArrayEquals(Packets.DNS, Packets.parse(reply).source);
        byte[] unknown = {(byte)198,18,2,2};
        assertNull(e.toVpn(packet(LOCAL4, unknown, 40000, 443, 6), 1000));
        byte[] fake = learn(e, "example.com", REAL4);
        DomainEngine changed = new DomainEngine(new DomainRules("other.test", "example.com"), true, e.save());
        assertNull(changed.toVpn(packet(LOCAL4, fake, 40000, 443, 6), 1000));
        byte[] fragmented = packet(LOCAL4, fake, 40000, 443, 6); Packets.put16(fragmented, 6, 0x2000);
        assertNull(e.toVpn(fragmented, 1000));
    }
    @Test public void malformedDnsMutations() {
        DomainEngine e = engine(true);
        byte[] q = query("example.com", 1), good = response(q, REAL4);
        int state = 12345;
        for (int i = 0; i < 10000; i++) {
            byte[] bad = good.clone();
            state = state * 1664525 + 1013904223;
            bad[(state & Integer.MAX_VALUE) % bad.length] ^= (byte)(state >>> 24);
            try { e.dns(q, bad); } catch (IllegalArgumentException expected) { }
        }
    }

    public static void main(String[] args) {
        DomainEngineTest t = new DomainEngineTest();
        t.suffixRules(); t.includeExcludeAndDnssec(); t.nativeIpv6OrSuppression();
        t.natRoundTripAllTransports(); t.sharedCdnAndPortCollision(); t.persistenceAndFlowLifetime();
        t.cnameAndMalformedResponses(); t.udpReplyAndFailClosed(); t.malformedDnsMutations();
        System.out.println("PASS: Android domain engine, DNS, persistent mappings, TCP/UDP IPv4/IPv6 NAT, checksums, CDN collisions and 10000 malformed DNS mutations");
    }
}
