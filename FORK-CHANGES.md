# Changes from OConnect v1.17.0

[Русский](FORK-CHANGES-RU.md)

This fork is maintained separately from upstream OConnect. The first public source snapshot, dated 2026-11-20, contains the following changes.

- Automatic ocserv dynamic split include and exclude, bounded XML and DNS parsing, and a direct TCP/UDP path.
- A routes screen with the domain and network rules applied to the current session.
- Optional logging of DNS matches and routing decisions for new TCP/UDP flows.
- A separate application ID, name and icon, plus English and Russian app language settings.
- A standalone Windows APK build and a release signing step. The inherited Xposed hook and legacy crash-reporting integration are omitted.
- A synthetic ocserv XML fixture and unit tests for routing, DNS and the direct TCP/UDP relay.

See [COPYING](COPYING), [doc/LICENSE.txt](doc/LICENSE.txt) and [third-party/README.md](third-party/README.md) for attribution, licensing and sources.
