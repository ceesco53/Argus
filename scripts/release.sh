#!/bin/bash
# Builds, signs, notarizes and publishes an Argus release with a Sparkle update feed.
#
# One-time setup (see README, "Releasing"):
#   - a Developer ID Application certificate in your Keychain
#   - notarization credentials:  xcrun notarytool store-credentials argus-notary ...
#   - scripts/setup-updates.sh
# For each release, raise MARKETING_VERSION and CURRENT_PROJECT_VERSION in project.yml first.
set -euo pipefail
cd "$(dirname "$0")/.."

notary_profile=${ARGUS_NOTARY_PROFILE:-argus-notary}
version=$(awk -F'"' '/MARKETING_VERSION:/ {print $2}' project.yml)
build=$(awk -F'"' '/CURRENT_PROJECT_VERSION:/ {print $2}' project.yml)
tag="v$version"
out=build/release

fail() { echo "error: $*" >&2; exit 1; }
command -v xcodegen >/dev/null || fail "xcodegen is required (brew install xcodegen)"
command -v gh >/dev/null || fail "the GitHub CLI is required (brew install gh)"
grep -qE '^ARGUS_UPDATE_PUBLIC_KEY *= *[^ ]+' Config/Local.xcconfig 2>/dev/null || fail "run scripts/setup-updates.sh first"
security find-identity -v -p codesigning | grep -q "Developer ID Application" || fail "no Developer ID Application certificate in the Keychain"
gh release view "$tag" >/dev/null 2>&1 && fail "release $tag already exists; raise MARKETING_VERSION in project.yml"
[ -z "$(git status --porcelain)" ] || fail "commit your changes first, so the release matches the repository"

echo "==> Building Argus $version ($build)"
rm -rf "$out/Argus.xcarchive" "$out/export" "$out/feed"
mkdir -p "$out/feed"
xcodegen generate >/dev/null
xcodebuild -project Argus.xcodeproj -scheme Argus -configuration Release -derivedDataPath "$out/DerivedData" \
  -archivePath "$out/Argus.xcarchive" -allowProvisioningUpdates ARGUS_FILTER_ENABLED=YES archive | tail -1

cat > "$out/ExportOptions.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>method</key><string>developer-id</string>
	<key>signingStyle</key><string>automatic</string>
</dict>
</plist>
PLIST
xcodebuild -exportArchive -archivePath "$out/Argus.xcarchive" -exportPath "$out/export" \
  -exportOptionsPlist "$out/ExportOptions.plist" -allowProvisioningUpdates | tail -1
app="$out/export/Argus.app"

echo "==> Notarizing"
ditto -c -k --keepParent "$app" "$out/notarize.zip"
xcrun notarytool submit "$out/notarize.zip" --keychain-profile "$notary_profile" --wait
xcrun stapler staple "$app"

echo "==> Packaging and signing the update"
zip="$out/feed/Argus-$version.zip"
ditto -c -k --keepParent "$app" "$zip"
repository=$(gh repo view --json nameWithOwner --jq .nameWithOwner)
"$out/DerivedData/SourcePackages/artifacts/sparkle/Sparkle/bin/generate_appcast" \
  --download-url-prefix "https://github.com/$repository/releases/download/$tag/" "$out/feed"

echo "==> Publishing $tag"
gh release create "$tag" "$zip" "$out/feed/appcast.xml" --title "Argus $version" --generate-notes
echo "Done: https://github.com/$repository/releases/tag/$tag"
