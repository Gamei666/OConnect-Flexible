// SPDX-License-Identifier: GPL-2.0-or-later
package app.openconnect.domains;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.util.Arrays;

/** SOCKS5 numeric-address codec (no implicit DNS resolution). */
public final class SocksWire {
    private SocksWire() { }
    public static final class Target {
        public final InetAddress address;
        public final int port;
        public final byte[] payload;
        Target(InetAddress address, int port, byte[] payload) { this.address = address; this.port = port; this.payload = payload; }
        public String key() { return Packets.hex(address.getAddress()) + ":" + port; }
    }
    public static Target readTarget(DataInputStream in) throws IOException {
        int type = in.readUnsignedByte(), n = type == 1 ? 4 : type == 4 ? 16 : 0;
        if (n == 0) throw new IOException("SOCKS requires a numeric destination");
        byte[] ip = new byte[n]; in.readFully(ip);
        return new Target(InetAddress.getByAddress(ip), in.readUnsignedShort(), null);
    }
    public static void writeTarget(DataOutputStream out, InetAddress address, int port) throws IOException {
        byte[] ip = address.getAddress(); out.writeByte(ip.length == 4 ? 1 : 4); out.write(ip); out.writeShort(port);
    }
    public static Target datagram(byte[] data, int length) throws IOException {
        if (length < 10 || length > data.length || data[0] != 0 || data[1] != 0 || data[2] != 0) throw new IOException("Unsupported SOCKS UDP frame");
        ByteArrayInputStream bytes = new ByteArrayInputStream(data, 3, length - 3);
        Target target = readTarget(new DataInputStream(bytes));
        if (target.port == 0) throw new IOException("Invalid UDP port");
        int offset = length - bytes.available();
        return new Target(target.address, target.port, Arrays.copyOfRange(data, offset, length));
    }
    public static byte[] datagram(InetAddress address, int port, byte[] payload, int length) {
        byte[] ip = address.getAddress(), result = new byte[6 + ip.length + length];
        result[3] = (byte)(ip.length == 4 ? 1 : 4); System.arraycopy(ip, 0, result, 4, ip.length);
        Packets.put16(result, 4 + ip.length, port); System.arraycopy(payload, 0, result, 6 + ip.length, length);
        return result;
    }
}
