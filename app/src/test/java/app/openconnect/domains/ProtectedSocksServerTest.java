package app.openconnect.domains;

import org.junit.Test;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.Assert.*;

public class ProtectedSocksServerTest {
    private final AtomicInteger protectedTcp = new AtomicInteger(), protectedUdp = new AtomicInteger();
    private ProtectedSocksServer server() throws IOException {
        return new ProtectedSocksServer(new ProtectedSocksServer.Protector() {
            public void tcp(Socket s, InetAddress d) throws IOException {
                assertFalse(s.isConnected());
                assertTrue("TCP_NODELAY must be set before protecting the socket", s.getTcpNoDelay());
                protectedTcp.incrementAndGet();
            }
            public void udp(DatagramSocket s) { assertFalse(s.isConnected()); protectedUdp.incrementAndGet(); }
        }, ignored -> {});
    }
    private static Socket login(ProtectedSocksServer server, String password) throws IOException {
        Socket s = new Socket("127.0.0.1", server.port()); s.setSoTimeout(5000);
        DataInputStream in = new DataInputStream(s.getInputStream()); DataOutputStream out = new DataOutputStream(s.getOutputStream());
        out.write(new byte[] {5, 1, 2}); out.flush(); assertEquals(5, in.readUnsignedByte()); assertEquals(2, in.readUnsignedByte());
        byte[] user = server.username.getBytes(StandardCharsets.US_ASCII), pass = password.getBytes(StandardCharsets.US_ASCII);
        out.writeByte(1); out.writeByte(user.length); out.write(user); out.writeByte(pass.length); out.write(pass); out.flush();
        assertEquals(1, in.readUnsignedByte()); assertEquals(password.equals(server.password) ? 0 : 1, in.readUnsignedByte());
        return s;
    }
    private static SocksWire.Target request(Socket socket, int command, InetAddress ip, int port) throws IOException {
        DataOutputStream out = new DataOutputStream(socket.getOutputStream()); DataInputStream in = new DataInputStream(socket.getInputStream());
        out.write(new byte[] {5, (byte)command, 0}); SocksWire.writeTarget(out, ip, port); out.flush();
        assertEquals(5, in.readUnsignedByte()); assertEquals(0, in.readUnsignedByte()); assertEquals(0, in.readUnsignedByte());
        return SocksWire.readTarget(in);
    }
    @Test public void tcpEchoAndHalfCloseThroughProtectedSocket() throws Exception {
        ExecutorService workers = Executors.newSingleThreadExecutor();
        byte[] payload = new byte[40000]; for (int i = 0; i < payload.length; i++) payload[i] = (byte)i;
        try (ServerSocket echo = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")); ProtectedSocksServer server = server();
             Socket client = login(server, server.password)) {
            echo.setSoTimeout(5000);
            Future<?> peer = workers.submit(() -> {
                try (Socket accepted = echo.accept()) {
                    accepted.setSoTimeout(5000); byte[] received = accepted.getInputStream().readAllBytes();
                    assertArrayEquals(payload, received); accepted.getOutputStream().write(received);
                } catch (IOException e) { throw new UncheckedIOException(e); }
            });
            request(client, 1, InetAddress.getByName("127.0.0.1"), echo.getLocalPort());
            client.getOutputStream().write(payload); client.shutdownOutput();
            assertArrayEquals(payload, client.getInputStream().readAllBytes()); peer.get(10, TimeUnit.SECONDS);
            assertEquals(1, protectedTcp.get());
        } finally { workers.shutdownNow(); }
    }
    @Test public void udpEchoThroughProtectedSocket() throws Exception {
        ExecutorService workers = Executors.newSingleThreadExecutor(); byte[] payload = {1, 2, 3, 4, 5};
        try (DatagramSocket echo = new DatagramSocket(new InetSocketAddress("127.0.0.1", 0)); ProtectedSocksServer server = server();
             Socket control = login(server, server.password); DatagramSocket client = new DatagramSocket()) {
            echo.setSoTimeout(5000); client.setSoTimeout(5000);
            Future<?> peer = workers.submit(() -> {
                try {
                    byte[] bytes = new byte[1000]; DatagramPacket packet = new DatagramPacket(bytes, bytes.length); echo.receive(packet);
                    assertArrayEquals(payload, Arrays.copyOf(bytes, packet.getLength())); echo.send(packet);
                } catch (IOException e) { throw new UncheckedIOException(e); }
            });
            SocksWire.Target relay = request(control, 3, InetAddress.getByName("0.0.0.0"), 0);
            byte[] frame = SocksWire.datagram(InetAddress.getByName("127.0.0.1"), echo.getLocalPort(), payload, payload.length);
            client.send(new DatagramPacket(frame, frame.length, relay.address, relay.port));
            byte[] bytes = new byte[1000]; DatagramPacket response = new DatagramPacket(bytes, bytes.length); client.receive(response);
            SocksWire.Target result = SocksWire.datagram(bytes, response.getLength());
            assertEquals(echo.getLocalPort(), result.port); assertArrayEquals(payload, result.payload);
            peer.get(10, TimeUnit.SECONDS); assertEquals(1, protectedUdp.get());
        } finally { workers.shutdownNow(); }
    }
    @Test public void rejectsInvalidAuthentication() throws Exception {
        try (ProtectedSocksServer server = server(); Socket client = login(server, "wrong-password")) {
            assertEquals(-1, client.getInputStream().read()); assertEquals(0, protectedTcp.get()); assertEquals(0, protectedUdp.get());
        }
    }
    @Test public void ipv6UdpCodecAndFragmentRejection() throws Exception {
        InetAddress ipv6 = InetAddress.getByName("2001:db8::8"); byte[] payload = {8, 9};
        byte[] frame = SocksWire.datagram(ipv6, 443, payload, payload.length);
        SocksWire.Target result = SocksWire.datagram(frame, frame.length);
        assertEquals(ipv6, result.address); assertEquals(443, result.port); assertArrayEquals(payload, result.payload);
        frame[2] = 1; assertThrows(IOException.class, () -> SocksWire.datagram(frame, frame.length));
        assertThrows(IOException.class, () -> SocksWire.datagram(new byte[2], 2));
    }
}
