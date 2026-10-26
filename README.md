# Argus

A hundred-eyed guardian for your Mac's network. Argus shows every connection every app makes, asks before
unknown connections go through, and blocks what you don't want, with a menu bar status item, a monitor,
a world map, rules, profiles, community blocklists, packet capture and a command line tool.

![icon](Argus/Resources/Assets.xcassets/AppIcon.appiconset/icon_256x256.png)

## Highlights

- **A calm start.** A learning period quietly records what your apps do for a few days, then a single
  review screen lets you trust or block each app, instead of a flood of alerts on day one.
- **Alerts that help you decide.** Each alert suggests an answer and says why; waiting alerts are grouped
  by app so you can answer an app's alerts at once.
- **Never interrupts a call.** During video calls, or while the screen is locked, Argus decides on its own
  (following a confident suggestion) and keeps the decisions for review.
- **Something not working?** The troubleshooter shows what Argus blocked for the app you're using and
  checks what it would do with any website; notifications tell you when the app in front was blocked.
- **Undo.** Every change to rules, profiles, blocklists and settings can be undone, from a message
  right after the change or from Recent Changes (⌥⌘Z undoes the latest).
- **Health checks.** Argus notices when DNS or the internet stops working, says whether it's the cause,
  and pauses itself while you sign in to hotel or airport Wi-Fi.
- **Pause** for 1, 5, 30 or 60 minutes from the menu bar, Control Center, Shortcuts or `argus pause`.
- **Weekly report** and **data usage warnings**, desktop **widgets**, Siri and Shortcuts actions, and
  **iCloud sync** of rules between your Macs.

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
   For iCloud sync of rules, also set `ARGUS_ICLOUD_ENABLED = YES` once Xcode is signed in to your
   developer account, so automatic signing can add the iCloud capability.
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
argus learn 3d                              # quiet learning period, then review in the app
argus test news.google.com --process Safari # what would happen, and why
argus changes && argus undo                 # recent changes; undo the latest
argus report --days 7                       # blocked, most-blocked domains, new apps
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
| `-ArgusDebugDownloadLocation YES` | Downloads the location database at launch |
| `-ArgusDebugMenu YES` | Shows the status menu's content in a normal window |
| `-hasCompletedOnboarding YES` | Skips the welcome guide |

## Releasing

Releases are signed with Developer ID, notarized, and published on GitHub Releases with a Sparkle
update feed, so installed copies update themselves.

One-time setup:

1. In Xcode › Settings › Accounts › Manage Certificates, add a **Developer ID Application** certificate.
2. Store notarization credentials (an [app-specific password](https://support.apple.com/102654)):
   ```sh
   xcrun notarytool store-credentials argus-notary --apple-id YOUR_APPLE_ID --team-id YOUR_TEAM_ID
   ```
3. Create the update-signing key and configure the feed:
   ```sh
   scripts/setup-updates.sh
   ```
   The private key stays in your login Keychain; back it up as the script describes. Losing it means
   existing installs can't verify future updates.

For each release, raise `MARKETING_VERSION` and `CURRENT_PROJECT_VERSION` in `project.yml`, commit,
then run `scripts/release.sh`. It archives, exports with Developer ID, notarizes and staples, signs
the update and writes `appcast.xml`, and creates the GitHub release with both attached.

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
