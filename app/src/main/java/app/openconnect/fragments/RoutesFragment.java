// SPDX-License-Identifier: GPL-2.0-or-later
package app.openconnect.fragments;

import android.app.Fragment;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import java.util.List;

import app.openconnect.R;
import app.openconnect.core.OpenVpnService;
import app.openconnect.core.RoutingDetails;
import app.openconnect.core.VPNConnector;

public class RoutesFragment extends Fragment {
    private VPNConnector connector;

    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        View screen = inflater.inflate(R.layout.routes, container, false);
        TextView summary = screen.findViewById(R.id.routes_summary);
        ViewGroup sections = screen.findViewById(R.id.routes_sections);

        connector = new VPNConnector(getActivity(), false) {
            private RoutingDetails displayed;

            @Override
            public void onUpdate(OpenVpnService service) {
                RoutingDetails details = service.getRoutingDetails();
                if (displayed == details) return;
                displayed = details;
                sections.removeAllViews();

                if (details == null) {
                    summary.setText(R.string.routes_disconnected);
                    return;
                }

                switch (details.source) {
                    case SERVER_DOMAINS:
                        summary.setText(R.string.routes_server_rules);
                        break;
                    case PROFILE_DOMAINS:
                        summary.setText(R.string.routes_profile_rules);
                        break;
                    default:
                        summary.setText(R.string.routes_ip_rules);
                }

                addSection(inflater, sections, R.string.routes_domain_include, details.includedDomains);
                addSection(inflater, sections, R.string.routes_domain_exclude, details.excludedDomains);
                addSection(inflater, sections, R.string.routes_network_include, details.includedNetworks);
                addSection(inflater, sections, R.string.routes_network_exclude, details.excludedNetworks);
            }
        };
        return screen;
    }

    private void addSection(LayoutInflater inflater, ViewGroup sections, int title, List<String> values) {
        View section = inflater.inflate(R.layout.route_section, sections, false);
        TextView heading = section.findViewById(R.id.route_section_title);
        TextView entries = section.findViewById(R.id.route_section_entries);
        heading.setText(title);
        if (values.isEmpty()) {
            entries.setText(R.string.routes_empty);
            entries.setTextIsSelectable(false);
        } else {
            entries.setText(TextUtils.join("\n", values));
        }
        sections.addView(section);
    }

    @Override
    public void onDestroyView() {
        connector.unbind();
        connector = null;
        super.onDestroyView();
    }
}
