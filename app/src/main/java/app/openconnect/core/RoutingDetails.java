// SPDX-License-Identifier: GPL-2.0-or-later
package app.openconnect.core;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;

/** Displayable rules for the current connection, without opaque server options. */
public final class RoutingDetails {
    public enum Source { SERVER_DOMAINS, PROFILE_DOMAINS, IP_ROUTES }

    public final Source source;
    public final List<String> includedDomains;
    public final List<String> excludedDomains;
    public final List<String> includedNetworks;
    public final List<String> excludedNetworks;

    RoutingDetails(Source source, Collection<String> includedDomains, Collection<String> excludedDomains,
            Collection<String> includedNetworks, Collection<String> excludedNetworks) {
        this.source = source;
        this.includedDomains = snapshot(includedDomains);
        this.excludedDomains = snapshot(excludedDomains);
        this.includedNetworks = snapshot(includedNetworks);
        this.excludedNetworks = snapshot(excludedNetworks);
    }

    private static List<String> snapshot(Collection<String> rules) {
        return Collections.unmodifiableList(new ArrayList<>(new LinkedHashSet<>(rules)));
    }
}
