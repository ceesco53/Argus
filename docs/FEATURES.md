# Everything Argus does

[← Back to Argus](../README.md)

## Seeing

- **Network Monitor** of every connection every app makes: server, location, port, protocol, data in and
  out, and whether it's open now. Group by app or by domain, filter to blocked, unanswered or new this
  week, and search across everything; the search tells you at once whether anything matching is blocked.
- **Web traffic under the right app.** Connections WebKit makes for Safari, Mail and other apps are
  shown under that app, with WebKit as the helper.
- **World Map** of where your data goes, sized by traffic, with the servers in each country.
- **Live traffic** charts for the whole Mac and for each app, by second, minute and hour.
- **Weekly report**: connections, what was blocked and by what, the most-blocked servers and apps, new apps.
- **Data usage warnings** when an app moves more than you'd expect in a day.

## Deciding

- **Alerts** hold a new connection until you answer, with a suggested answer and its reasons (from
  reference blocklists, the app's identity and your earlier answers). Answer for this server, the whole
  domain or any server; for this port or any; once, until the app quits, for a while, or forever.
- **Waiting alerts grouped by app**, answered together, plus a learning period that records quietly for a
  few days and a single review screen afterwards.
- **Never interrupts a call**: during video calls or with the screen locked, Argus decides on its own
  and keeps the decisions for review.
- **Ask, allow silently or deny silently** for anything without a rule; pause protection for 1–60 minutes.

## Rules

- Rules by program, server (host, domain, IP address or network, local network), port, protocol and
  direction, for every user or one, in every profile or one.
- **Temporary rules** (until quit, until restart, for a time) and **priority rules** that nothing can override.
- Problems flagged: duplicate rules and rules another rule always overrules.
- **Undo** any change from a message right after it or from Recent Changes (⌥⌘Z).

## Blocklists and profiles

- **Community blocklists** from a built-in catalog (HaGeZi, Steven Black, OISD, FireHOL and more) or any
  URL, in hosts, domain-list, IP-set and Little Snitch `.lsrules` formats, refreshed automatically.
  IP lists never touch your local network.
- **Profiles** (Home, Office, Coffee Shop…) with their own rules and mode, switched automatically when
  the Mac joins one of their networks.

## Security

- **Code signatures** checked on every connection. Rules made from alerts remember the signature, so a
  replaced or tampered program can't inherit them, and an app updated with a new signature is handled
  without fuss.
- **Packet sniffer detection**: a warning when a program opens `/dev/bpf` to read raw traffic.
- **Packet capture** of chosen connections to `.pcap` files for Wireshark.
- **Settings lock**: changes need an administrator password.

## Everywhere

- **Menu bar** status with live traffic, recently blocked connections (allow in one click) and what's active.
- **Troubleshooter**: pick an app to see what was blocked and why, check any website, and get notified
  when the app in front was blocked. **Health checks** notice when DNS or the internet stops working,
  say whether Argus is the cause, and pause it while you sign in to hotel or airport Wi-Fi.
- **Desktop widgets**, **Control Center** controls (macOS 26), and **Siri and Shortcuts** actions.
- **iCloud sync** of rules, profiles and blocklists between your Macs.
- **[Command line tool](COMMAND-LINE.md)** for everything, scriptable and usable over SSH.
- **Automatic updates**, signed and notarized.
- **Monitor mode** for builds without the Network Extension entitlement: everything except holding and
  blocking connections. See [Building](BUILDING.md).
