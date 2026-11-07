# Development

[← Back to Argus](../README.md)

```sh
cd ArgusKit && swift test                                   # engine, parsers, PCAP (checked with tcpdump), IPC
swift Tools/ArtworkGenerator.swift Argus/Resources/Assets.xcassets   # re-render icon, mascot, menu glyph
```

See [Building](BUILDING.md) for building the app, and [Architecture](ARCHITECTURE.md) for how it fits together.

## Debug launch arguments

Debug builds accept launch arguments for working on the UI without the filter:

| Argument | Effect |
|---|---|
| `-ArgusDemo YES` | Runs on made-up activity instead of the real filter (see below) |
| `-ArgusDebugSection monitor` | Opens the main window on that section (`overview`, `monitor`, `map`, `rules`, `ads`, `blocklists`, `profiles`, `security`, `capture`, `troubleshoot`) |
| `-ArgusDebugSheet digest` | Opens a sheet on top (`review`, `digest`, `changes`) |
| `-ArgusDebugSearch doubleclick` | Starts the Network Monitor with that search |
| `-ArgusDebugTroubleshoot Safari` | Starts Troubleshoot with that app picked |
| `-ArgusDebugPageCheck YES` | With `-ArgusDebugTroubleshoot`, shows a finished page check on that app's activity (`search` shows a culprit search under way) |
| `-ArgusDebugAlert YES` | Shows sample connection alerts |
| `-ArgusDebugMenu YES` | Shows the status menu's content in a normal window |
| `-ArgusDebugWindowSize 1440x900` | Sizes the main window |
| `-ArgusDebugDownloadLocation YES` | Downloads the location database at launch |
| `-hasCompletedOnboarding YES` | Skips the welcome guide |
| `-acceptedTermsVersion 1` | Skips the terms of use (for this launch only) |

## Demo mode and the README screenshots

`-ArgusDemo YES` runs Argus on a week of made-up but realistic activity: common apps, public websites,
a few ad and tracker domains that get blocked, and generic profiles. It runs its own engine in a
temporary folder, never connects to the real filter, and stays away from the real configuration,
iCloud sync, the widgets and notifications, so screenshots never show anything personal. The same
week is generated every time.

The screenshots in `docs/images` were taken this way, with a neutral time zone so the World Map's
"This Mac" pin doesn't give away where you are:

```sh
TZ=America/Los_Angeles build/DerivedData/Build/Products/Debug/Argus.app/Contents/MacOS/Argus \
  -ArgusDemo YES -hasCompletedOnboarding YES -acceptedTermsVersion 1 \
  -ArgusDebugWindowSize 1440x900 -ArgusDebugSection overview
```

Capture a window with ⇧⌘4 then Space, or `screencapture -o -l <window number> out.png`.

## Diagnosing the filter

`argus diagnostics` (not listed in `argus help`) switches parts of the filter off, to narrow down how it
affects a connection without rebuilding:

| Flag | Effect |
|---|---|
| `bareAllow` | Allowed connections get a plain verdict: no byte counts, no DNS inspection |
| `noReports` | No byte-count reports for any connection |
| `noUDPReports` | No byte-count reports for UDP (QUIC) connections |
| `noDNSPeek` | Don't read DNS answers to learn hostnames |

```sh
argus diagnostics noReports     # set one or more flags
argus diagnostics none          # back to normal
```

The filter also logs how long its decisions take, once a minute, and any decision slower than 100 ms:

```sh
log show --last 10m --predicate 'process ENDSWITH ".Argus.Filter" AND category == "filter"'
```
