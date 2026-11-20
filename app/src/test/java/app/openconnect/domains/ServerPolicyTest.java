package app.openconnect.domains;

import org.junit.Test;
import java.nio.charset.StandardCharsets;
import java.util.*;
import static org.junit.Assert.*;
import static app.openconnect.domains.ServerPolicy.Action.*;
import static app.openconnect.domains.ServerPolicy.numeric;

public class ServerPolicyTest {
    static String xml(String in, String out) {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?><config-auth client=\"vpn\" type=\"complete\"><config client=\"vpn\" type=\"private\"><opaque is-for=\"vpn-client\"><custom-attr>" +
            (in == null ? "" : "<dynamic-split-include-domains><![CDATA[" + in + "]]></dynamic-split-include-domains>") +
            (out == null ? "" : "<dynamic-split-exclude-domains><![CDATA[" + out + "]]></dynamic-split-exclude-domains>") +
            "</custom-attr></opaque></config></config-auth>";
    }
    static ServerPolicy policy(String in, String out, boolean full, boolean v6, boolean bypass) {
        Map<String,String> opts = new HashMap<>();
        opts.put("X-CSTP-Post-Auth-XML", xml(in, out));
        opts.put("X-CSTP-Client-Bypass-Protocol", Boolean.toString(bypass));
        return ServerPolicy.from(opts, Collections.singletonList(full ? "0.0.0.0/0" : "10.110.8.0/255.255.255.0"),
                Arrays.asList("192.0.2.0/24", "198.51.100.0/24", "172.16.0.0/12"), true, v6);
    }
    @Test public void exampleOcservPostAuthXml() throws Exception {
        String fixture;
        try (java.io.InputStream in = getClass().getResourceAsStream("/ocserv-post-auth.xml")) {
            assertNotNull(in); fixture = new String(in.readAllBytes(), StandardCharsets.UTF_8).trim();
        }
        ServerPolicy p = ServerPolicy.from(Collections.singletonMap("x-cstp-post-auth-xml", fixture),
                Collections.emptyList(), Arrays.asList("192.0.2.0/24", "198.51.100.0/24", "172.16.0.0/12"), true, false);
        assertEquals(0, p.includeCount()); assertEquals(3, p.excludeCount()); assertTrue(p.full4);
        for (String d : new String[] {"video.example.com", "cdn.video.example.com", "auth.example.net", "news.example.org"}) {
            assertEquals(d, DIRECT, p.domain(d, 4));
        }
        assertEquals(NONE, p.domain("notvideo.example.com", 4));
        assertEquals(VPN, p.address(numeric("203.0.113.7"), NONE));
        for (String ip : new String[] {"192.0.2.8", "198.51.100.8", "172.18.5.6"}) assertEquals(DIRECT, p.address(numeric(ip), VPN));
    }
    @Test public void splitIncludeAndStaticRoutes() {
        ServerPolicy p = policy("example.com", null, false, false, false);
        assertFalse(p.full4); assertEquals(VPN, p.domain("www.EXAMPLE.com.", 4));
        assertEquals(DIRECT, p.address(numeric("203.0.113.7"), NONE));
        assertEquals(VPN, p.address(numeric("10.110.8.9"), NONE));
        assertEquals(VPN, p.address(numeric("203.0.113.7"), p.domain("example.com", 4)));
    }
    @Test public void mixedPolicyPriorityDependsOnBaseMode() {
        ServerPolicy full = policy("inside.example.com", "example.com", true, true, false);
        ServerPolicy split = policy("example.com", "inside.example.com", false, true, false);
        assertEquals(VPN, full.domain("inside.example.com", 4));
        assertEquals(DIRECT, full.domain("other.example.com", 4));
        assertEquals(DIRECT, split.domain("inside.example.com", 4));
        assertEquals(VPN, split.domain("other.example.com", 4));
    }
    @Test public void missingAddressFamilyAndGateway() {
        ServerPolicy p = policy("example.com", "direct.test", true, false, true);
        byte[] v6 = numeric("2001:db8::8");
        assertEquals(DIRECT, p.address(v6, NONE)); assertEquals(DROP, p.address(v6, VPN));
        assertEquals(DROP, policy("example.com", null, true, false, false).address(v6, NONE));
        p.gateway("vpn.example.com", "203.0.113.9");
        assertTrue(p.gatewayHost("VPN.EXAMPLE.COM.")); assertEquals(DIRECT, p.domain("vpn.example.com", 4));
        assertEquals(DIRECT, p.address(numeric("203.0.113.9"), VPN));
    }
    @Test public void noPolicyAndEmptyRecognizedPolicy() {
        assertNull(ServerPolicy.from(Collections.emptyMap(), null, null, true, false));
        assertNull(ServerPolicy.from(Collections.singletonMap("X-CSTP-Post-Auth-XML", xml(null, null)), null, null, true, false));
        assertEquals(0, policy("", "", true, false, true).includeCount());
    }
    @Test public void unsafeMalformedAndDuplicateXmlRejected() {
        for (String xml : new String[] {"<config-auth>", "<!DOCTYPE x SYSTEM 'file:///etc/passwd'><x/>",
                "<!DOCTYPE x [<!ENTITY y 'example.com'>]><x>&y;</x>", "x".repeat(65537),
                "<custom-attr><dynamic-split-include-domains><x/></dynamic-split-include-domains></custom-attr>",
                xml("https://example.com/path", null),
                "<custom-attr><dynamic-split-exclude-domains/><dynamic-split-exclude-domains/></custom-attr>"}) {
            assertThrows(IllegalArgumentException.class, () -> ServerPolicy.from(Collections.singletonMap("X-CSTP-Post-Auth-XML", xml), null, null, true, false));
        }
        Map<String,String> duplicate = new HashMap<>(); duplicate.put("X-CSTP-Post-Auth-XML", xml("a.test", null)); duplicate.put("x-cstp-post-auth-xml", xml("b.test", null));
        assertThrows(IllegalArgumentException.class, () -> ServerPolicy.from(duplicate, null, null, true, false));
    }
    @Test public void numericMasksAndSignature() {
        assertThrows(IllegalArgumentException.class, () -> numeric("face"));
        assertThrows(IllegalArgumentException.class, () -> numeric("example.com"));
        assertThrows(IllegalArgumentException.class, () -> new ServerPolicy.Prefix("10.0.0.0/255.0.255.0"));
        assertThrows(IllegalArgumentException.class, () -> new ServerPolicy.Prefix("10.0.0.0/33"));
        assertTrue(new ServerPolicy.Prefix("2001:db8::/32").contains(numeric("2001:db8:1234::5")));
        assertEquals(policy("a.test,b.test", "c.test", true, true, false).signature(), policy("b.test,a.test", "c.test", true, true, false).signature());
        assertNotEquals(policy("a.test", null, true, true, false).signature(), policy("b.test", null, true, true, false).signature());
    }
}
