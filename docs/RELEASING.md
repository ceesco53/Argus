# Releasing

[← Back to Argus](../README.md)

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
