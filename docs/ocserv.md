# ocserv dynamic split tunneling

[Русский](ocserv-RU.md)

The client reads the Cisco-style domain attributes from the server's `X-CSTP-Post-Auth-XML` header. Enter the server URL in an Android VPN profile and connect. Any manual domain fallback in the profile applies when the server sends no dynamic policy.

## Full tunnel with exclusions

```ini
route = default
no-route = 192.0.2.0/24
custom-header = X-CSTP-Post-Auth-XML: <?xml version="1.0" encoding="UTF-8"?><config-auth client="vpn" type="complete" aggregate-auth-version="2"><config client="vpn" type="private"><opaque is-for="vpn-client"><custom-attr><dynamic-split-exclude-domains><![CDATA[video.example.com,news.example.net]]></dynamic-split-exclude-domains></custom-attr></opaque></config></config-auth>
```

Matched domains, their subdomains, and the excluded subnet use the direct path. In an IPv4-only VPN, the server's bypass protocol setting also affects IPv6.

## Split tunnel with inclusions

Use explicit server routes in place of `route = default`. This example adds domains to a VPN that otherwise only routes a private subnet.

```ini
route = 10.24.0.0/16
custom-header = X-CSTP-Post-Auth-XML: <?xml version="1.0" encoding="UTF-8"?><config-auth client="vpn" type="complete" aggregate-auth-version="2"><config client="vpn" type="private"><opaque is-for="vpn-client"><custom-attr><dynamic-split-include-domains><![CDATA[example.com]]></dynamic-split-include-domains><dynamic-split-exclude-domains><![CDATA[video.example.com]]></dynamic-split-exclude-domains></custom-attr></opaque></config></config-auth>
```

With a split-tunnel base, `example.com` and its subdomains use VPN, except `video.example.com` and its subdomains. When domain rules overlap in a full tunnel, include has priority. Static IP exclusions have priority in both modes.

## Runtime limits

The client maps observed DNS answers to destination IPs for their DNS TTL. Shared IPs, cached addresses, Android Private DNS, and app-specific encrypted DNS can affect which path is selected. Existing sessions keep their selected path. Direct traffic supports TCP and UDP. The dynamic mode requires an IPv4 VPN address, an IPv4 DNS server and VPN MTU of at least 1280. Reconnect the profile after changing the server policy.

## Diagnostics

Turn on **Settings → Advanced → Dynamic split diagnostics**, make a new connection to the site or service you want to check, and open **Connection details → Log**. The setting is off by default and can be changed during a VPN session.

- `DOMAIN: server policy active` confirms that domain rules arrived from ocserv.
- `SPLIT DNS` records IP addresses learned for matching domains, the policy direction and the TTL. It also reports selected DNS filtering decisions.
- `SPLIT FLOW` shows the selected path and reason for a new TCP or UDP flow, such as `DIRECT reason=dynamic_exclude` or `VPN reason=dynamic_include`. A selection describes routing. A direct connection error can still appear separately.

Entries are rate-limited. Existing flows keep their selected path, so open a new connection when testing a rule. Review domain names and destination IP addresses before sharing the log.
