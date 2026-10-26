import Foundation
import Sparkle

/// Automatic updates through Sparkle. Dormant unless the build carries an update feed and the
/// public key its updates are signed with (see README, "Releasing").
@MainActor
final class Updater {
    static let shared = Updater()

    private let controller: SPUStandardUpdaterController?

    private init() {
        let info = Bundle.main.infoDictionary ?? [:]
        let feed = info["SUFeedURL"] as? String ?? ""
        let key = info["SUPublicEDKey"] as? String ?? ""
        controller = feed.isEmpty || key.isEmpty ? nil
            : SPUStandardUpdaterController(startingUpdater: true, updaterDelegate: nil, userDriverDelegate: nil)
    }

    var isConfigured: Bool { controller != nil }

    func checkForUpdates() { controller?.checkForUpdates(nil) }

    var checksAutomatically: Bool {
        get { controller?.updater.automaticallyChecksForUpdates ?? false }
        set { controller?.updater.automaticallyChecksForUpdates = newValue }
    }
}
