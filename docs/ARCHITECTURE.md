# Architecture

[← Back to Argus](../README.md)

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

## Suggested answers

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

## Rule precedence

When several rules match, Argus compares them in this order and the first difference wins:
priority rules › rules for a specific program › the narrower server (host or IP › deeper domain › network
› local network › any) › a specific port › a specific protocol › deny over allow. Blocklist entries behave
like "deny any program" rules, so allowing a specific app always overrides a list, and an allow rule
exactly as narrow as a list entry wins over it. IP lists never apply to local-network addresses (some,
like FireHOL, list the private ranges, which would otherwise cut a Mac off from its own router and DNS).
