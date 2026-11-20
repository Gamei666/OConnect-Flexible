// SPDX-License-Identifier: GPL-2.0-or-later
package app.openconnect.domains;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Bounded DNS decoder. Synthesized address answers deliberately clear DNSSEC AD. */
public final class DnsWire {
    private DnsWire() { }
    public interface Mapper { byte[] map(String name, byte[] real); }
    public static final class Question {
        public final String name;
        public final int type, end, id;
        Question(String name, int type, int end, int id) { this.name = name; this.type = type; this.end = end; this.id = id; }
    }
    private static final class Record {
        String owner, alias;
        int type;
        long ttl;
        byte[] address;
    }
    private static String name(byte[] p, int[] offset) {
        int pos = offset[0], end = -1;
        StringBuilder out = new StringBuilder();
        for (int hops = 0; hops < 128 && pos < p.length; hops++) {
            int n = p[pos++] & 255;
            if (n == 0) {
                offset[0] = end < 0 ? pos : end;
                return out.toString().toLowerCase(Locale.ROOT);
            }
            if ((n & 192) == 192) {
                if (pos >= p.length) break;
                int ptr = ((n & 63) << 8) | (p[pos] & 255);
                if (ptr >= pos - 1) break;
                if (end < 0) end = pos + 1;
                pos = ptr; continue;
            }
            if (n > 63 || n > p.length - pos || out.length() + n + 1 > 254) break;
            if (out.length() != 0) out.append('.');
            for (int i = 0; i < n; i++) {
                int c = p[pos++] & 255;
                if (c <= 32 || c >= 127 || c == '.') throw new IllegalArgumentException("Invalid DNS label");
                out.append((char)c);
            }
        }
        throw new IllegalArgumentException("Malformed DNS name");
    }
    public static Question question(byte[] p) {
        if (p.length < 12 || Packets.u16(p, 4) != 1 || (p[2] & 0x78) != 0) throw new IllegalArgumentException("Unsupported DNS question");
        int[] at = {12};
        String domain = name(p, at);
        if (p.length - at[0] < 4 || Packets.u16(p, at[0] + 2) != 1) throw new IllegalArgumentException("Unsupported DNS class");
        return new Question(domain, Packets.u16(p, at[0]), at[0] + 4, Packets.u16(p, 0));
    }
    public static byte[] error(byte[] query, int code) {
        if (query.length < 12) return null;
        try {
            Question q = question(query);
            byte[] out = Arrays.copyOf(query, q.end);
            out[2] = (byte)(0x80 | (query[2] & 1)); out[3] = (byte)(0x80 | code);
            Arrays.fill(out, 6, 12, (byte)0);
            return out;
        } catch (IllegalArgumentException e) { return null; }
    }
    private static long u32(byte[] p, int o) { return ((long)Packets.u16(p, o) << 16) | Packets.u16(p, o + 2); }

    public static final class AddressAnswer {
        public final byte[] address;
        public final long ttl;
        AddressAnswer(byte[] address, long ttl) { this.address = address; this.ttl = ttl; }
    }
    /** Correlated addresses reachable through CNAMEs, with each address's TTL. */
    public static List<AddressAnswer> addresses(byte[] query, byte[] response) {
        Question q = question(query), a = question(response);
        if (q.id != a.id || !q.name.equals(a.name) || q.type != a.type || (response[2] & 0x80) == 0 || (response[2] & 2) != 0) {
            throw new IllegalArgumentException("Unrelated or truncated DNS response");
        }
        List<AddressAnswer> result = new ArrayList<>();
        if ((response[3] & 15) != 0 || (q.type != 1 && q.type != 28)) return result;
        int count = Packets.u16(response, 6);
        if (count > 256) throw new IllegalArgumentException("Too many DNS answers");
        List<Record> records = new ArrayList<>();
        int[] at = {a.end};
        for (int i = 0; i < count; i++) {
            Record r = new Record(); r.owner = name(response, at);
            if (response.length - at[0] < 10) throw new IllegalArgumentException("Short DNS record");
            r.type = Packets.u16(response, at[0]); int cls = Packets.u16(response, at[0] + 2);
            r.ttl = u32(response, at[0] + 4); int n = Packets.u16(response, at[0] + 8); at[0] += 10;
            int end = at[0] + n;
            if (end > response.length) throw new IllegalArgumentException("Short DNS data");
            if (cls == 1 && r.type == 5) {
                r.alias = name(response, at);
                if (at[0] != end) throw new IllegalArgumentException("Bad CNAME length");
            } else if (cls == 1 && ((r.type == 1 && n == 4) || (r.type == 28 && n == 16))) {
                r.address = Arrays.copyOfRange(response, at[0], end);
            }
            records.add(r); at[0] = end;
        }
        String terminal = q.name; long aliasTtl = 86400;
        for (int hop = 0; ; hop++) {
            Record alias = null;
            for (Record r : records) if (r.alias != null && r.owner.equals(terminal)) { alias = r; break; }
            if (alias == null) break;
            if (hop >= 16) throw new IllegalArgumentException("CNAME cycle");
            terminal = alias.alias; aliasTtl = Math.min(aliasTtl, alias.ttl);
        }
        for (Record r : records) if (r.address != null && r.type == q.type && r.owner.equals(terminal)) {
            result.add(new AddressAnswer(r.address, Math.min(aliasTtl, r.ttl)));
        }
        return result;
    }

    public static byte[] transform(byte[] query, byte[] response, boolean selected, boolean ipv6, Mapper mapper) {
        Question q = question(query), answer = question(response);
        if (q.id != answer.id || !q.name.equals(answer.name) || q.type != answer.type || (response[2] & 0x80) == 0 || (response[2] & 2) != 0) {
            throw new IllegalArgumentException("Unrelated or truncated DNS response");
        }
        if (!selected) return response;
        if ((response[3] & 15) != 0) return error(query, response[3] & 15);
        // HTTPS/SVCB IP hints would bypass fake addresses. Let applications use A/AAAA.
        if (q.type == 64 || q.type == 65 || q.type == 255 || (q.type == 28 && !ipv6)) return error(query, 0);
        if (q.type != 1 && q.type != 28) return response;
        int count = Packets.u16(response, 6);
        if (count > 256) throw new IllegalArgumentException("Too many DNS answers");
        int[] at = {answer.end};
        List<Record> records = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            Record r = new Record(); r.owner = name(response, at);
            if (response.length - at[0] < 10) throw new IllegalArgumentException("Short DNS record");
            r.type = Packets.u16(response, at[0]); int cls = Packets.u16(response, at[0] + 2);
            r.ttl = u32(response, at[0] + 4); int size = Packets.u16(response, at[0] + 8); at[0] += 10;
            int end = at[0] + size;
            if (end > response.length) throw new IllegalArgumentException("Short DNS data");
            if (cls == 1 && r.type == 5) {
                r.alias = name(response, at);
                if (at[0] != end) throw new IllegalArgumentException("Bad CNAME length");
            } else if (cls == 1 && ((r.type == 1 && size == 4) || (r.type == 28 && size == 16))) {
                r.address = Arrays.copyOfRange(response, at[0], end);
            }
            records.add(r); at[0] = end;
        }
        String terminal = q.name;
        long ttl = 300;
        for (int hop = 0; ; hop++) {
            Record alias = null;
            for (Record r : records) if (r.alias != null && r.owner.equals(terminal)) { alias = r; break; }
            if (alias == null) break;
            if (hop >= 16) throw new IllegalArgumentException("CNAME cycle");
            terminal = alias.alias; ttl = Math.min(ttl, alias.ttl);
        }
        Map<String, byte[]> addresses = new LinkedHashMap<>();
        for (Record r : records) if (r.address != null && r.type == q.type && r.owner.equals(terminal)) {
            if (addresses.size() >= 8) break;
            addresses.put(Packets.hex(r.address), r.address); ttl = Math.min(ttl, r.ttl);
        }
        byte[] header = error(query, 0);
        if (header == null) throw new IllegalArgumentException("Invalid question");
        Packets.put16(header, 6, addresses.size());
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(header, 0, header.length);
        for (byte[] real : addresses.values()) {
            byte[] mapped = mapper.map(q.name, real);
            byte[] rr = new byte[12 + mapped.length];
            rr[0] = (byte)0xc0; rr[1] = 12; Packets.put16(rr, 2, q.type); Packets.put16(rr, 4, 1);
            Packets.put16(rr, 8, (int)Math.max(1, ttl)); Packets.put16(rr, 10, mapped.length);
            System.arraycopy(mapped, 0, rr, 12, mapped.length);
            out.write(rr, 0, rr.length);
        }
        return out.toByteArray();
    }
}
