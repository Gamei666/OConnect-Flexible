// SPDX-License-Identifier: GPL-2.0-or-later
package app.openconnect.domains;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Session NAT for synthetic VPN addresses. Existing flows keep their own mapping.
 * DNS TTL does not expire mappings or connections. Persistent fake addresses are
 * never reassigned to another domain when the VPN is reconnected. */
public final class DomainEngine {
    private static final int MAX_BINDINGS = 4096, MAX_FLOWS = 8192;
    private static final class Binding {
        final String name;
        final byte[] real, fake;
        Binding(String name, byte[] real, byte[] fake) { this.name = name; this.real = real.clone(); this.fake = fake.clone(); }
    }
    private static final class Flow {
        Binding binding;
        byte[] local;
        String outKey, inKey;
        int protocol, originalPort, translatedPort;
        long seen;
    }
    private final DomainRules rules;
    private final boolean ipv6;
    private final Map<String, Binding> realBindings = new LinkedHashMap<>();
    private final Map<String, Binding> fakeBindings = new HashMap<>();
    private final Map<String, Flow> outgoing = new HashMap<>(), incoming = new HashMap<>();
    private int nextAddress = 2, nextPort = 49152;
    private long swept;

    public DomainEngine(DomainRules rules, boolean ipv6, List<String> saved) {
        this.rules = rules; this.ipv6 = ipv6;
        if (saved == null) return;
        for (String line : saved) {
            String[] parts = line.split(" ");
            if (parts.length != 3 || realBindings.size() >= MAX_BINDINGS) throw new IllegalArgumentException("Invalid domain mapping file");
            byte[] fake = Packets.unhex(parts[0]), real = Packets.unhex(parts[2]);
            String name = DomainRules.normalize(parts[1]);
            int id = fake.length == 4
                    ? (((fake[1] & 255) - 18) << 16) | ((fake[2] & 255) << 8) | (fake[3] & 255)
                    : ((fake[13] & 255) << 16) | ((fake[14] & 255) << 8) | (fake[15] & 255);
            if (!Packets.fake(fake) || fake.length != real.length || id < 2 || id > 131071 ||
                    fakeBindings.containsKey(Packets.hex(fake))) throw new IllegalArgumentException("Invalid saved fake address");
            Binding b = new Binding(name, real, fake);
            String key = name + ":" + Packets.hex(real);
            if (realBindings.containsKey(key)) throw new IllegalArgumentException("Duplicate saved address");
            realBindings.put(key, b); fakeBindings.put(Packets.hex(fake), b);
            nextAddress = Math.max(nextAddress, id + 1);
        }
    }

    public synchronized List<String> save() {
        List<String> lines = new ArrayList<>();
        for (Binding b : realBindings.values()) lines.add(Packets.hex(b.fake) + " " + b.name + " " + Packets.hex(b.real));
        return lines;
    }
    public synchronized int bindingCount() { return realBindings.size(); }

    private byte[] allocate(String domain, byte[] real) {
        String canonical = DomainRules.normalize(domain), key = canonical + ":" + Packets.hex(real);
        Binding b = realBindings.get(key);
        if (b != null) return b.fake.clone();
        if (realBindings.size() >= MAX_BINDINGS || nextAddress > 131071 || Packets.fake(real)) {
            throw new IllegalArgumentException("Domain address pool exhausted or conflicting upstream address");
        }
        int id = nextAddress++;
        byte[] fake;
        if (real.length == 4) fake = new byte[] {(byte)198, (byte)(18 + (id >> 16)), (byte)(id >> 8), (byte)id};
        else {
            fake = Arrays.copyOf(Packets.V6_PREFIX, 16);
            fake[13] = (byte)(id >> 16); fake[14] = (byte)(id >> 8); fake[15] = (byte)id;
        }
        b = new Binding(canonical, real, fake);
        realBindings.put(key, b); fakeBindings.put(Packets.hex(fake), b);
        return fake.clone();
    }

    public synchronized byte[] dns(byte[] query, byte[] response) {
        return DnsWire.transform(query, response, rules.includes(DnsWire.question(query).name), ipv6, this::allocate);
    }

    private static String inKey(byte[] real, int protocol, int remotePort, int localPort) {
        return Packets.hex(real) + ":" + protocol + ":" + remotePort + ":" + localPort;
    }
    private void sweep(long now) {
        if (now - swept < 30000) return;
        swept = now;
        Iterator<Flow> it = outgoing.values().iterator();
        while (it.hasNext()) {
            Flow f = it.next();
            if (now - f.seen > (f.protocol == 6 ? 86400000 : 180000)) { incoming.remove(f.inKey); it.remove(); }
        }
    }

    /** null means drop; no selected-domain traffic ever falls back to direct. */
    public synchronized byte[] toVpn(byte[] packet, long now) {
        sweep(now);
        Packets.View p = Packets.parse(packet);
        if (p == null || !p.hasPorts()) return null;
        Binding b = fakeBindings.get(Packets.hex(p.destination));
        if (b == null || !rules.includes(b.name) || (p.version == 6 && !ipv6)) return null;
        String key = Packets.hex(p.destination) + ":" + Packets.hex(p.source) + ":" + p.protocol + ":" + p.sourcePort() + ":" + p.destinationPort();
        Flow f = outgoing.get(key);
        if (f == null) {
            if (outgoing.size() >= MAX_FLOWS) return null;
            int port = p.sourcePort();
            for (int tries = 0; incoming.containsKey(inKey(b.real, p.protocol, p.destinationPort(), port)); tries++) {
                if (tries >= 16384) return null;
                port = nextPort++; if (nextPort > 65535) nextPort = 49152;
            }
            f = new Flow(); f.binding = b; f.local = p.source.clone(); f.protocol = p.protocol;
            f.originalPort = p.sourcePort(); f.translatedPort = port; f.outKey = key;
            f.inKey = inKey(b.real, p.protocol, p.destinationPort(), port);
            outgoing.put(key, f); incoming.put(f.inKey, f);
        }
        f.seen = now;
        Packets.rewrite(p, false, b.real, p.destinationPort());
        Packets.rewrite(p, true, p.source, f.translatedPort);
        return packet;
    }

    public synchronized byte[] fromVpn(byte[] packet, long now) {
        sweep(now);
        Packets.View p = Packets.parse(packet);
        if (p == null || !p.hasPorts()) return null;
        Flow f = incoming.get(inKey(p.source, p.protocol, p.sourcePort(), p.destinationPort()));
        if (f == null || !Arrays.equals(f.local, p.destination)) return null;
        f.seen = now;
        Packets.rewrite(p, true, f.binding.fake, p.sourcePort());
        Packets.rewrite(p, false, p.destination, f.originalPort);
        return packet;
    }
}
