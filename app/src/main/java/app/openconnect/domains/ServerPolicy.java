// SPDX-License-Identifier: GPL-2.0-or-later
package app.openconnect.domains;

import java.io.StringReader;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import javax.xml.parsers.SAXParserFactory;
import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.DefaultHandler;

/** Cisco-compatible post-auth custom attributes supplied by ocserv. Never executes XML. */
public final class ServerPolicy {
    public enum Action { NONE, VPN, DIRECT, DROP }

    enum Decision {
        GATEWAY(Action.DIRECT),
        STATIC_EXCLUDE(Action.DIRECT),
        DYNAMIC_EXCLUDE(Action.DIRECT),
        DYNAMIC_INCLUDE(Action.VPN),
        DYNAMIC_INCLUDE_NO_VPN_FAMILY(Action.DROP),
        FAMILY_BYPASS(Action.DIRECT),
        FAMILY_BLOCKED(Action.DROP),
        STATIC_INCLUDE(Action.VPN),
        FULL_TUNNEL_DEFAULT(Action.VPN),
        SPLIT_TUNNEL_DEFAULT(Action.DIRECT),
        VPN_DNS(Action.VPN),
        FLOW_LIMIT(Action.DROP);

        final Action action;

        Decision(Action action) {
            this.action = action;
        }
    }
    public static final class Prefix {
        final byte[] network;
        final int bits;
        public Prefix(String text) {
            String[] parts = text.trim().split("/", -1);
            network = numeric(parts[0]);
            if (parts.length > 2) throw new IllegalArgumentException("Invalid server route");
            int b = network.length * 8;
            if (parts.length == 2) {
                if (parts[1].contains(".")) {
                    byte[] mask = numeric(parts[1]);
                    if (mask.length != 4 || network.length != 4) throw new IllegalArgumentException("Invalid route mask");
                    b = 0; boolean zero = false;
                    for (byte value : mask) for (int i = 7; i >= 0; i--) {
                        if ((value & (1 << i)) != 0) {
                            if (zero) throw new IllegalArgumentException("Non-contiguous route mask");
                            b++;
                        } else zero = true;
                    }
                } else b = Integer.parseInt(parts[1]);
            }
            if (b < 0 || b > network.length * 8) throw new IllegalArgumentException("Invalid route prefix");
            bits = b;
        }
        boolean contains(byte[] address) {
            if (network.length != address.length) return false;
            for (int i = 0; i < bits; i++) if (((network[i / 8] ^ address[i / 8]) & (128 >> (i % 8))) != 0) return false;
            return true;
        }
    }

    public static byte[] numeric(String s) {
        if (s == null || s.isEmpty() || (!s.matches("[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+") && !(s.contains(":") && s.matches("[0-9a-fA-F:]+")))) {
            throw new IllegalArgumentException("Expected a numeric IP address");
        }
        try { return InetAddress.getByName(s).getAddress(); }
        catch (Exception e) { throw new IllegalArgumentException("Invalid IP address"); }
    }

    private final List<Prefix> routes, exclusions;
    private final Set<String> include, exclude;
    public final boolean ipv4, ipv6, bypassMissingFamily, full4, full6;
    private String gatewayHost;
    private byte[] gateway;

    private ServerPolicy(Parsed parsed, List<String> routes, List<String> exclusions,
                         boolean ipv4, boolean ipv6, boolean bypass) {
        include = parsed.include; exclude = parsed.exclude;
        this.routes = prefixes(routes); this.exclusions = prefixes(exclusions);
        this.ipv4 = ipv4; this.ipv6 = ipv6; this.bypassMissingFamily = bypass;
        full4 = full(this.routes, 4); full6 = full(this.routes, 16);
    }
    private static List<Prefix> prefixes(List<String> values) {
        if (values == null) return Collections.emptyList();
        if (values.size() > 2048) throw new IllegalArgumentException("Too many server routes");
        List<Prefix> result = new ArrayList<>();
        for (String s : values) result.add(new Prefix(s));
        return result;
    }
    private static boolean full(List<Prefix> routes, int size) {
        boolean present = false;
        for (Prefix p : routes) if (p.network.length == size) {
            present = true; if (p.bits == 0) return true;
        }
        return !present;
    }
    public static String option(Map<String, String> options, String name) {
        String result = null;
        for (Map.Entry<String, String> e : options.entrySet()) if (e.getKey().equalsIgnoreCase(name)) {
            if (result != null) throw new IllegalArgumentException("Duplicate server policy header");
            result = e.getValue();
        }
        return result;
    }
    public static ServerPolicy from(Map<String, String> options, List<String> routes, List<String> exclusions,
                                    boolean ipv4, boolean ipv6) {
        String xml = option(options, "X-CSTP-Post-Auth-XML");
        if (xml == null) return null;
        Parsed parsed = parse(xml);
        if (!parsed.present) return null;
        return new ServerPolicy(parsed, routes, exclusions, ipv4, ipv6,
                "true".equalsIgnoreCase(option(options, "X-CSTP-Client-Bypass-Protocol")));
    }
    public int includeCount() { return include.size(); }
    public int excludeCount() { return exclude.size(); }
    public Set<String> includedDomains() { return Collections.unmodifiableSet(include); }
    public Set<String> excludedDomains() { return Collections.unmodifiableSet(exclude); }
    /** Canonical public policy only; never includes opaque XML session data. */
    public String signature() {
        List<String> values = new ArrayList<>();
        for (String s : include) values.add("i:" + s);
        for (String s : exclude) values.add("e:" + s);
        for (Prefix p : routes) values.add("r:" + Packets.hex(p.network) + "/" + p.bits);
        for (Prefix p : exclusions) values.add("x:" + Packets.hex(p.network) + "/" + p.bits);
        Collections.sort(values);
        return ipv4 + ":" + ipv6 + ":" + bypassMissingFamily + ":" + values;
    }
    public void gateway(String host, String address) {
        if (host != null) try { gatewayHost = DomainRules.normalize(host); } catch (IllegalArgumentException ignored) { }
        if (address != null) try { gateway = numeric(address); } catch (IllegalArgumentException ignored) { }
    }
    public boolean gatewayHost(String name) {
        if (gatewayHost == null) return false;
        try { return gatewayHost.equals(DomainRules.normalize(name)); } catch (IllegalArgumentException e) { return false; }
    }
    private static boolean matches(Set<String> domains, String name) {
        for (String domain : domains) if (name.equals(domain) || name.endsWith("." + domain)) return true;
        return false;
    }
    public boolean hasDomainRule(String name) {
        try {
            String n = DomainRules.normalize(name);
            return matches(include, n) || matches(exclude, n);
        } catch (IllegalArgumentException e) { return false; }
    }
    /** Enhanced exclude: include wins. Enhanced include: exclude wins. */
    public Action domain(String name, int size) {
        if (gatewayHost(name)) return Action.DIRECT;
        final String n;
        try { n = DomainRules.normalize(name); } catch (IllegalArgumentException e) { return Action.NONE; }
        boolean in = matches(include, n), out = matches(exclude, n);
        return combine(in, out, size);
    }
    public Action combine(boolean in, boolean out, int size) {
        if (size == 4 ? full4 : full6) return in ? Action.VPN : out ? Action.DIRECT : Action.NONE;
        return out ? Action.DIRECT : in ? Action.VPN : Action.NONE;
    }
    public Action address(byte[] ip, Action dynamic) {
        return decide(ip, dynamic).action;
    }

    Decision decide(byte[] ip, Action dynamic) {
        if (gateway != null && java.util.Arrays.equals(gateway, ip)) return Decision.GATEWAY;
        for (Prefix p : exclusions) if (p.contains(ip)) return Decision.STATIC_EXCLUDE;
        boolean family = ip.length == 4 ? ipv4 : ipv6;
        if (dynamic == Action.DIRECT) return Decision.DYNAMIC_EXCLUDE;
        if (dynamic == Action.VPN) return family ? Decision.DYNAMIC_INCLUDE : Decision.DYNAMIC_INCLUDE_NO_VPN_FAMILY;
        if (!family) return bypassMissingFamily ? Decision.FAMILY_BYPASS : Decision.FAMILY_BLOCKED;
        if (ip.length == 4 ? full4 : full6) return Decision.FULL_TUNNEL_DEFAULT;
        for (Prefix p : routes) if (p.contains(ip)) return Decision.STATIC_INCLUDE;
        return Decision.SPLIT_TUNNEL_DEFAULT;
    }

    private static final class Parsed extends DefaultHandler {
        Set<String> include = new LinkedHashSet<>(), exclude = new LinkedHashSet<>();
        int depth, customDepth = -1, valueDepth = -1;
        String tag;
        boolean present, seenInclude, seenExclude;
        StringBuilder value;
        @Override public void startElement(String uri, String local, String qualified, Attributes attributes) throws SAXException {
            if (++depth > 32) throw new SAXException("Policy nesting limit");
            String name = local.isEmpty() ? qualified : local;
            if (value != null) throw new SAXException("Nested domain attribute");
            if (name.equals("custom-attr")) customDepth = depth;
            if (customDepth >= 0 && (name.equals("dynamic-split-include-domains") || name.equals("dynamic-split-exclude-domains"))) {
                if (name.contains("-include-") ? seenInclude : seenExclude) throw new SAXException("Duplicate domain attribute");
                if (name.contains("-include-")) seenInclude = true; else seenExclude = true;
                present = true; tag = name; valueDepth = depth; value = new StringBuilder();
            }
        }
        @Override public void characters(char[] c, int start, int length) throws SAXException {
            if (value != null) {
                if (value.length() + length > 20000) throw new SAXException("Domain policy too large");
                value.append(c, start, length);
            }
        }
        @Override public void endElement(String uri, String local, String qualified) throws SAXException {
            if (value != null && depth == valueDepth) {
                Set<String> list = tag.contains("-include-") ? include : exclude;
                String data = value.toString().trim();
                if (!data.isEmpty()) for (String token : data.split("[,;\\s]+")) {
                    if (include.size() + exclude.size() >= 2048) throw new SAXException("Too many domain rules");
                    try { list.add(DomainRules.normalize(token)); }
                    catch (IllegalArgumentException e) { throw new SAXException("Invalid domain in server policy"); }
                }
                value = null; valueDepth = -1;
            }
            if (depth == customDepth) customDepth = -1;
            depth--;
        }
    }
    private static Parsed parse(String xml) {
        if (xml.length() > 65536 || xml.toUpperCase(Locale.ROOT).contains("<!DOCTYPE") || xml.toUpperCase(Locale.ROOT).contains("<!ENTITY")) {
            throw new IllegalArgumentException("Unsafe or oversized post-auth XML");
        }
        try {
            SAXParserFactory factory = SAXParserFactory.newInstance();
            factory.setNamespaceAware(true); factory.setValidating(false);
            XMLReader reader = factory.newSAXParser().getXMLReader();
            for (String feature : new String[] {"http://xml.org/sax/features/external-general-entities", "http://xml.org/sax/features/external-parameter-entities", "http://apache.org/xml/features/nonvalidating/load-external-dtd"}) {
                try { reader.setFeature(feature, false); } catch (SAXException ignored) { }
            }
            reader.setEntityResolver((publicId, systemId) -> new InputSource(new StringReader("")));
            Parsed parsed = new Parsed(); reader.setContentHandler(parsed); reader.setErrorHandler(parsed);
            reader.parse(new InputSource(new StringReader(xml)));
            return parsed;
        } catch (Exception e) {
            // Never expose raw XML: post-auth XML can contain session credentials.
            throw new IllegalArgumentException("Invalid server dynamic-split XML policy");
        }
    }
}
