# Argus

A hundred-eyed guardian for your Mac's network. Argus shows every connection every app makes, asks before
unknown connections go through, and blocks what you don't want, with a menu bar status item, a monitor,
a world map, rules, profiles, community blocklists, packet capture and a command line tool.

![icon](Argus/Resources/Assets.xcassets/AppIcon.appiconset/icon_256x256.png)

## Two ways Argus runs

| | Monitor mode | Filter mode |
|---|---|---|
| Needs | Nothing (any build) | A paid Apple Developer team + the Network Extension entitlement |
| Sees every connection, traffic, locations | ✓ (via `nettop`) | ✓ (from the filter) |
| Hostnames | Reverse DNS (marked `≈`) | What the app actually asked for, plus names learned from DNS answers |
| Alerts that hold a connection | — | ✓ |
| Enforces rules and blocklists | Shows what *would* be blocked | ✓ |
| PCAP capture | — | ✓ |

Rules, profiles and blocklists made in monitor mode carry over automatically the first time the filter runs.

## Building

Requirements: Xcode 27 (macOS 15 SDK or newer), [XcodeGen](https://github.com/yonaskolb/XcodeGen).

```sh
brew install xcodegen
xcodegen generate            # creates Argus.xcodeproj from project.yml
open Argus.xcodeproj         # or:
xcodebuild -scheme Argus -configuration Release -derivedDataPath build/DerivedData build
```

The default build signs locally without restricted entitlements and runs in **monitor mode**.

### Enabling the network filter

Apple only grants the Network Extension and System Extension entitlements to paid Apple Developer Program
teams, so the firewall needs your team:

1. Create `Config/Local.xcconfig` (git-ignored). Bundle identifiers are unique across all developers, so
   pick a prefix of your own:
   ```
   DEVELOPMENT_TEAM = ABCDE12345
   ARGUS_FILTER_ENABLED = YES
   ARGUS_BUNDLE_PREFIX = com.example
   ```
2. Build with automatic signing allowed to register the identifiers and capabilities (Network Extensions,
   System Extension, app group `<TEAM>.<prefix>.Argus`):
   ```sh
   xcodegen generate
   xcodebuild -scheme Argus -configuration Release -destination 'platform=macOS' \
     -derivedDataPath build/DerivedData -allowProvisioningUpdates build
   ```
3. Move `Argus.app` to `/Applications` (macOS only loads system extensions from there), open it,
   click **Install Filter** and allow it in System Settings › General › Login Items & Extensions.

For distribution outside the App Store, archive with a Developer ID certificate and notarize.

## Architecture

```
┌──────────────── Argus.app (menu bar agent, SwiftUI) ───────────────┐
│ AppModel ── ArgusClient ──┬── XPC ──────────► ArgusFilter (system   │
│   views, alerts, map      │                    extension, root,      │
│   FilterManager           │                    NEFilterDataProvider) │
│   NetworkWatcher          │                      └ FirewallCore      │
│   GeoLocator              └── in-process ──► MonitorEngine           │
│                                                └ FirewallCore        │
│                                                └ NettopMonitor       │
│                                                └ Unix socket ◄── argus CLI (monitor mode)
└─────────────────────────────────────────────────────────────────────┘
                       argus CLI ── XPC ──► ArgusFilter (filter mode)
```

- **ArgusKit** (Swift package) holds everything that isn't UI: the rule engine and its precedence rules,
  profiles, blocklist/rule-group parsers (hosts, domain lists, IP sets, Little Snitch `.lsrules`), the DNS
  answer parser, the PCAP writer, activity and traffic statistics, code-signature and libproc helpers,
  admin authorization, and the message protocol shared by every transport.
- **FirewallCore** is the single source of truth. The same engine runs inside the filter or inside the app,
  so both modes behave identically apart from enforcement.
- **ArgusFilter** pauses unknown flows (`.pause()`), asks the app over XPC, and resumes them with the answer.
  It peeks at DNS responses to learn hostnames, and at payloads only while a capture is running.
- **IPC** is one Codable request/response/event protocol over three transports: NSXPC (app/CLI ↔ filter),
  a Unix socket (CLI ↔ in-app monitor) and an in-memory pipe (app ↔ in-app monitor).

### Suggested answers

Each alert carries a suggestion built from independent signals, shown with its reasons:

| Signal | Leans | Strength |
|---|---|---|
| Listed by HaGeZi Threat Intelligence (reference only) | Deny | Strong (overrides everything) |
| Listed by HaGeZi Multi Pro (reference only) | Deny, whole domain | Moderate |
| A known analytics/ads service, or `telemetry`-style names | Deny | Weak |
| The app's own server (the domain's brand is in the app's identifier, e.g. `com.google.Chrome` → `google.com`) | Allow | Moderate |
| Apple services / shared CDNs | Allow | Moderate / weak |
| Your rules for the same domain, and your earlier answers | Either | Moderate / weak |
| Unsigned or broken signature, incoming from the internet | Deny | Weak / moderate |

Reference lists are downloaded daily by the engine and never block anything themselves: a host on a
list you've *enabled* is blocked before anyone is asked, so only lists you haven't enabled can advise.
The suggested button becomes the default, and unanswered alerts can optionally follow a confident
suggestion (Settings › Alerts).

### Rule precedence

When several rules match, Argus compares them in this order and the first difference wins:
priority rules › rules for a specific program › the narrower server (host or IP › deeper domain › network
› local network › any) › a specific port › a specific protocol › deny over allow. Blocklist entries behave
like "deny any program" rules, so allowing a specific app always overrides a list, and an allow rule
exactly as narrow as a list entry wins over it. IP lists never apply to local-network addresses (some,
like FireHOL, list the private ranges, which would otherwise cut a Mac off from its own router and DNS).

## Command line

The tool is embedded at `Argus.app/Contents/Helpers/argus`. Install a link from Settings › Command Line.

```sh
argus status
argus rules add deny --process Safari --domain doubleclick.net
argus rules add allow --process /usr/bin/curl --host api.example.com --port 443 --proto tcp --for 2h
argus profiles activate Work
argus blocklists add hagezi-light          # or any URL; see `argus blocklists catalog`
argus log --follow
argus blocked                               # what was blocked recently, and why
argus allow news.google.com                 # always allow a host (add --domain or --process NAME)
argus pause 5m && argus resume              # allow everything for a while
sudo argus capture start --process curl --seconds 30 && argus capture save <id> out.pcap
argus backup argus.json && argus restore argus.json --merge
argus lock                                  # changes now need an administrator (or root)
```

Run `argus help` for everything. Over SSH, `sudo argus …` administers a locked Mac.

## Development

```sh
cd ArgusKit && swift test                                   # engine, parsers, PCAP (checked with tcpdump), IPC
swift Tools/ArtworkGenerator.swift Argus/Resources/Assets.xcassets   # re-render icon, mascot, menu glyph
```

Debug builds accept launch arguments for working on the UI without the filter:

| Argument | Effect |
|---|---|
| `-ArgusDebugSection monitor` | Opens the main window on that section (`overview`, `monitor`, `map`, `rules`, `blocklists`, `profiles`, `security`, `capture`) |
| `-ArgusDebugAlert YES` | Shows a sample connection alert |
| `-ArgusDebugMenu YES` | Shows the status menu's content in a normal window |
| `-ArgusDebugDownloadLocation YES` | Downloads the location database at launch |
| `-hasCompletedOnboarding YES` | Skips the welcome guide |

## Privacy

Nothing about your connections leaves the Mac. Argus downloads only what you ask for: blocklists from
their maintainers and, if you opt in, the public address registration files of the five regional internet
registries (ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC) for server locations.

## Known limitations

- Monitor mode observes after the fact; it can't hold or block a connection.
- Server locations are where an address block is *registered*, which for large CDNs may differ from where
  the server physically is.
- Without Local Network permission macOS hides the router's hardware address, so networks are recognised
  by router address until you click **Identify Router** in Profiles. Wi-Fi names need Location Services.
- The sandboxed filter can't inspect other users' processes for `/dev/bpf` access; detection is limited
  to what the sandbox allows.

## License

Argus is available under the [MIT License](LICENSE). Community blocklists and registry data are
downloaded at runtime from their maintainers and remain under their own licenses.
