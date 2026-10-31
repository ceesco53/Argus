# Building Argus

[← Back to Argus](../README.md)

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
