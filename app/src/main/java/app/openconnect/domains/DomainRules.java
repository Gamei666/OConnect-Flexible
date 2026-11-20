// SPDX-License-Identifier: GPL-2.0-or-later
package app.openconnect.domains;

import java.net.IDN;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Domain suffixes, with a label boundary. More specific wins; exclude wins ties. */
public final class DomainRules {
    private static final class Rule {
        final String domain;
        final boolean include;
        Rule(String domain, boolean include) { this.domain = domain; this.include = include; }
    }
    private final List<Rule> rules = new ArrayList<>();
    private String bypassHost;

    public DomainRules(String include, String exclude) {
        add(include, true);
        add(exclude, false);
        if (rules.stream().noneMatch(r -> r.include)) {
            throw new IllegalArgumentException("Add at least one include domain");
        }
    }

    public static String normalize(String input) {
        String s = input.trim();
        if (s.startsWith("*.")) s = s.substring(2);
        if (s.endsWith(".")) s = s.substring(0, s.length() - 1);
        s = IDN.toASCII(s, IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT);
        if (s.isEmpty() || s.length() > 253 || !s.contains(".")) {
            throw new IllegalArgumentException("Expected a domain name: " + input);
        }
        return s;
    }

    private void add(String input, boolean include) {
        if (input == null || input.trim().isEmpty()) return;
        for (String token : input.trim().split("[,;\\s]+")) {
            if (rules.size() >= 256) throw new IllegalArgumentException("Maximum 256 domain rules");
            rules.add(new Rule(normalize(token), include));
        }
    }

    public List<String> domains(boolean included) {
        List<String> result = new ArrayList<>();
        for (Rule rule : rules) {
            if (rule.include == included) result.add(rule.domain);
        }
        return result;
    }

    public boolean includes(String input) {
        final String name;
        try { name = normalize(input); } catch (IllegalArgumentException e) { return false; }
        if (name.equals(bypassHost)) return false;
        int best = -1;
        boolean included = false;
        for (Rule r : rules) {
            if ((name.equals(r.domain) || name.endsWith("." + r.domain)) &&
                    (r.domain.length() > best || (r.domain.length() == best && !r.include))) {
                best = r.domain.length();
                included = r.include;
            }
        }
        return included;
    }
    public void bypassHost(String host) {
        if (host == null) { bypassHost = null; return; }
        try { bypassHost = normalize(host); } catch (IllegalArgumentException e) { bypassHost = null; }
    }
}
