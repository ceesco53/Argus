# Everything Argus does

[← Back to Argus](../README.md)

## Seeing

- **Network Monitor** of every connection every app makes: server, location, port, protocol, data in and
  out, and whether it's open now. Group by app or by domain, filter to blocked, unanswered or new this
  week, and search across everything; the search tells you at once whether anything matching is blocked.
- **Web traffic under the right app.** Connections WebKit makes for Safari, Mail and other apps are
  shown under that app, with WebKit as the helper, and so are the connections of helpers an app runs
  from its own bundle (Chrome's network service, an Electron app's helpers). Rules for the app keep
  working when an update moves its helpers, and Rules offers to move rules written for a helper to its app.
- **World Map** of where your data goes, sized by traffic, with the servers in each country.
- **Live traffic** charts for the whole Mac and for each app, by second, minute and hour.
- **Weekly report**: connections, what was blocked and by what, the most-blocked servers and apps, new apps.
- **Data usage warnings** when an app moves more than you'd expect in a day.

## Deciding

- **Alerts** hold a new connection until you answer, with a suggested answer and its reasons (from
  reference blocklists, the app's identity and your earlier answers). Answer for this server, the whole
  domain or any server; for this port or any; once, until the app quits, for a while, or forever.
- **Fewer repeat alerts**: one answer covers a port over both TCP and UDP (a browser's HTTPS and HTTP/3
  are one alert), an alert starts on the whole domain once you've answered for another of its servers
  or more of them are waiting, and an app you keep allowing gets a one-click Allow Everywhere.
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

## Ads in browsers

- **One switch for how much to block** in Safari, Chrome, Firefox and other browsers: Off, Light, Normal
  or Pro, each one of HaGeZi's lists applied to browsers only, so other apps are never affected.
- **Your ad domains**: block what the list misses, allow what it breaks, or leave a domain to the list,
  from a list of every ad and tracking server your browsers reached and what Argus did about it. An
  allow beats every list, however specific the list's entry. One switch turns all your choices off,
  to see whether they're what breaks a site, and they sync between your Macs.
- **Rules for one browser, moved** into your ad domains so they apply in every browser, with
  anti-adblock servers offered for deletion instead.
- **Anti-adblock servers flagged** (Ad-Shield, Blockthrough): blocking them is what makes sites refuse
  to load, so Argus marks them everywhere and never suggests blocking them.

## Blocklists and profiles

- **Community blocklists** from a built-in catalog (HaGeZi, Steven Black, OISD, FireHOL and more) or any
  URL, in hosts, domain-list, IP-set and Little Snitch `.lsrules` formats, refreshed automatically,
  for every app or browsers only. IP lists never touch your local network.
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
  when the app in front was blocked. **Check a page**: Argus reloads it (asking the browser, with your
  permission) and lists everything it connects to and what was blocked by which list or rule. Let
  anything through, or block it, for 15 minutes and keep what works, or let Argus find what the page
  needs by letting half of the blocked servers through at a time. **Health checks** notice when DNS or
  the internet stops working, say whether Argus is the cause, and pause it while you sign in to hotel
  or airport Wi-Fi.
- **Desktop widgets**, **Control Center** controls (macOS 26), and **Siri and Shortcuts** actions.
- **iCloud sync** of rules, profiles and blocklists between your Macs.
- **[Command line tool](COMMAND-LINE.md)** for everything, scriptable and usable over SSH.
- **Automatic updates**, signed and notarized.
- **Monitor mode** for builds without the Network Extension entitlement: everything except holding and
  blocking connections. See [Building](BUILDING.md).
