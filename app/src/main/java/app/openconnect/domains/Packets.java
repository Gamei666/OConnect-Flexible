// SPDX-License-Identifier: GPL-2.0-or-later
package app.openconnect.domains;

import java.util.Arrays;

/** Raw IP packets; no Android dependency. Packet arrays are owned by the caller. */
public final class Packets {
    private Packets() { }
    public static final byte[] DNS = {(byte)198, 18, 0, 1};
    public static final byte[] V6_PREFIX = {(byte)0xfd, 0x42, 0x6f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0, 0, 0, 0};
    public static int u16(byte[] p, int o) { return ((p[o] & 255) << 8) | (p[o + 1] & 255); }
    public static void put16(byte[] p, int o, int n) { p[o] = (byte)(n >> 8); p[o + 1] = (byte)n; }
    public static int sum(byte[] p, int start, int end, int sum) {
        for (int i = start; i < end; i += 2) {
            sum += (p[i] & 255) << 8;
            if (i + 1 < end) sum += p[i + 1] & 255;
        }
        while ((sum >>> 16) != 0) sum = (sum & 65535) + (sum >>> 16);
        return sum;
    }
    public static final class View {
        public final byte[] data, source, destination;
        public final int version, length, transport, protocol;
        public final boolean fragment;
        View(byte[] p, int version, int length, int transport, int protocol, boolean fragment) {
            this.data = p; this.version = version; this.length = length;
            this.transport = transport; this.protocol = protocol; this.fragment = fragment;
            source = Arrays.copyOfRange(p, version == 4 ? 12 : 8, version == 4 ? 16 : 24);
            destination = Arrays.copyOfRange(p, version == 4 ? 16 : 24, version == 4 ? 20 : 40);
        }
        public int sourcePort() { return u16(data, transport); }
        public int destinationPort() { return u16(data, transport + 2); }
        public boolean hasPorts() {
            if (fragment) return false;
            if (protocol == 6 && length - transport >= 20) {
                int size = ((data[transport + 12] >>> 4) & 15) * 4;
                return size >= 20 && size <= length - transport;
            }
            return protocol == 17 && length - transport >= 8 && u16(data, transport + 4) == length - transport;
        }
    }

    public static View parse(byte[] p) {
        if (p.length < 20) return null;
        if ((p[0] >>> 4 & 15) == 4) {
            int header = (p[0] & 15) * 4, n = u16(p, 2);
            if (header < 20 || header > n || n != p.length) return null;
            return new View(p, 4, n, header, p[9] & 255, (u16(p, 6) & 0x3fff) != 0);
        }
        if ((p[0] >>> 4 & 15) != 6 || p.length < 40 || u16(p, 4) + 40 != p.length) return null;
        int pos = 40, proto = p[6] & 255;
        for (int i = 0; i < 8 && (proto == 0 || proto == 43 || proto == 60); i++) {
            if (p.length - pos < 8) return null;
            int n = ((p[pos + 1] & 255) + 1) * 8;
            if (n > p.length - pos) return null;
            proto = p[pos] & 255; pos += n;
        }
        return new View(p, 6, p.length, pos, proto, proto == 44);
    }

    public static boolean fake(byte[] address) {
        if (address.length == 4) return (address[0] & 255) == 198 && (address[1] & 254) == 18;
        if (address.length != 16) return false;
        for (int i = 0; i < 12; i++) if (address[i] != V6_PREFIX[i]) return false;
        return true;
    }

    /** RFC1624 incremental transport checksum correction; preserve UDPv4 zero checksum. */
    public static void rewrite(View v, boolean source, byte[] replacement, int port) {
        int addressOffset = v.version == 4 ? (source ? 12 : 16) : (source ? 8 : 24);
        int checksumOffset = v.transport + (v.protocol == 6 ? 16 : 6);
        int oldChecksum = u16(v.data, checksumOffset);
        int value = (~oldChecksum) & 65535;
        byte[] before = source ? v.source : v.destination;
        for (int i = 0; i < before.length; i += 2) {
            value += (~u16(before, i)) & 65535;
            value += u16(replacement, i);
            value = (value & 65535) + (value >>> 16);
        }
        int portOffset = v.transport + (source ? 0 : 2);
        value += (~u16(v.data, portOffset)) & 65535;
        value += port;
        while ((value >>> 16) != 0) value = (value & 65535) + (value >>> 16);
        if (oldChecksum != 0 || v.version == 6 || v.protocol != 17) {
            int updated = (~value) & 65535;
            put16(v.data, checksumOffset, updated == 0 && v.protocol == 17 ? 65535 : updated);
        }
        System.arraycopy(replacement, 0, v.data, addressOffset, before.length);
        put16(v.data, portOffset, port);
        if (v.version == 4) {
            put16(v.data, 10, 0);
            put16(v.data, 10, (~sum(v.data, 0, (v.data[0] & 15) * 4, 0)) & 65535);
        }
    }

    public static byte[] udpReply(View query, byte[] payload) {
        int header = query.version == 4 ? 20 : 40;
        byte[] p = new byte[header + 8 + payload.length];
        if (query.version == 4) {
            p[0] = 0x45; p[8] = 64; p[9] = 17; put16(p, 2, p.length);
            System.arraycopy(query.destination, 0, p, 12, 4);
            System.arraycopy(query.source, 0, p, 16, 4);
            put16(p, 10, (~sum(p, 0, 20, 0)) & 65535);
        } else {
            p[0] = 0x60; p[6] = 17; p[7] = 64; put16(p, 4, p.length - 40);
            System.arraycopy(query.destination, 0, p, 8, 16);
            System.arraycopy(query.source, 0, p, 24, 16);
        }
        put16(p, header, query.destinationPort()); put16(p, header + 2, query.sourcePort());
        put16(p, header + 4, p.length - header); System.arraycopy(payload, 0, p, header + 8, payload.length);
        int pseudo = sum(p, query.version == 4 ? 12 : 8, query.version == 4 ? 20 : 40, 17 + p.length - header);
        int checksum = (~sum(p, header, p.length, pseudo)) & 65535;
        put16(p, header + 6, checksum == 0 ? 65535 : checksum);
        return p;
    }

    public static String hex(byte[] p) {
        char[] out = new char[p.length * 2];
        for (int i = 0; i < p.length; i++) {
            out[2 * i] = "0123456789abcdef".charAt((p[i] & 255) >>> 4);
            out[2 * i + 1] = "0123456789abcdef".charAt(p[i] & 15);
        }
        return new String(out);
    }
    public static byte[] unhex(String s) {
        if (s.length() != 8 && s.length() != 32) throw new IllegalArgumentException("Invalid address length");
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(s.charAt(i * 2), 16), lo = Character.digit(s.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) throw new IllegalArgumentException("Invalid address");
            out[i] = (byte)((hi << 4) | lo);
        }
        return out;
    }
}
