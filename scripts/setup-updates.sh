#!/bin/bash
# One-time setup for signed automatic updates (Sparkle).
#
# Generates the EdDSA key pair Sparkle signs updates with. The private key is stored in your
# login Keychain and never leaves this Mac; the public key and the update feed address are
# written to Config/Local.xcconfig (git-ignored).
set -euo pipefail
cd "$(dirname "$0")/.."

xcodegen generate >/dev/null
xcodebuild -resolvePackageDependencies -project Argus.xcodeproj -scheme Argus -derivedDataPath build/release/DerivedData >/dev/null
bin=build/release/DerivedData/SourcePackages/artifacts/sparkle/Sparkle/bin
[ -x "$bin/generate_keys" ] || { echo "error: Sparkle's tools weren't found in $bin" >&2; exit 1; }

"$bin/generate_keys" >/dev/null # creates the key on first run, keeps the existing one after that
public_key=$("$bin/generate_keys" -p)
repository=$(gh repo view --json nameWithOwner --jq .nameWithOwner)
feed="https://github.com/$repository/releases/latest/download/appcast.xml"

touch Config/Local.xcconfig
sed -i '' '/^ARGUS_UPDATE_PUBLIC_KEY/d;/^ARGUS_UPDATE_FEED_URL/d' Config/Local.xcconfig
# Don't glue the new settings onto a last line that has no line break.
[ -s Config/Local.xcconfig ] && [ "$(tail -c 1 Config/Local.xcconfig)" != "" ] && echo >> Config/Local.xcconfig
# In .xcconfig files "//" starts a comment; "$()" (an empty setting) keeps the URL whole.
printf 'ARGUS_UPDATE_PUBLIC_KEY = %s\nARGUS_UPDATE_FEED_URL = %s\n' "$public_key" "${feed/:\/\//:/\$()/}" >> Config/Local.xcconfig
echo "Update signing is set up."
echo "  Public key: $public_key"
echo "  Feed:       $feed"
echo "Back up the private key with: $bin/generate_keys -x sparkle-private-key.txt (and keep that file safe)."
