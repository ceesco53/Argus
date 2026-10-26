import AppKit
import Foundation
import Observation

/// Notices when the user can't (or shouldn't) be interrupted by alerts, and which app they're using.
@MainActor @Observable
final class BusyDetector {
    private(set) var isBusy = false
    /// Why, in words: "in a call", "screen locked".
    private(set) var reason: String?
    /// The app the user was last working in (never Argus itself).
    private(set) var foregroundApp: NSRunningApplication?

    @ObservationIgnored var onChange: ((Bool) -> Void)?
    @ObservationIgnored private var screenLocked = false
    @ObservationIgnored private var displaysAsleep = false
    @ObservationIgnored private var callApp: String?
    @ObservationIgnored private var observers: [NSObjectProtocol] = []

    /// Video-call apps: while one of these is in front, Argus doesn't pop up alerts.
    static let callApps: [String: String] = [
        "us.zoom.xos": "Zoom", "com.microsoft.teams2": "Microsoft Teams", "com.microsoft.teams": "Microsoft Teams",
        "com.cisco.webexmeetingsapp": "Webex", "Cisco-Systems.Spark": "Webex", "com.apple.FaceTime": "FaceTime",
        "com.logmein.GoToMeeting": "GoTo Meeting", "com.google.Chrome.app.kjgfgldnnfoeklkmfkjfagphfepbbdan": "Google Meet",
        "com.skype.skype": "Skype", "com.ringcentral.RingCentral": "RingCentral",
    ]

    var isEnabled: Bool { UserDefaults.standard.object(forKey: "quietWhenBusy") as? Bool ?? true }

    func start() {
        let distributed = DistributedNotificationCenter.default()
        observers.append(distributed.addObserver(forName: .init("com.apple.screenIsLocked"), object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.screenLocked = true; self?.update() }
        })
        observers.append(distributed.addObserver(forName: .init("com.apple.screenIsUnlocked"), object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.screenLocked = false; self?.update() }
        })
        let workspace = NSWorkspace.shared.notificationCenter
        observers.append(workspace.addObserver(forName: NSWorkspace.screensDidSleepNotification, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.displaysAsleep = true; self?.update() }
        })
        observers.append(workspace.addObserver(forName: NSWorkspace.screensDidWakeNotification, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.displaysAsleep = false; self?.update() }
        })
        observers.append(workspace.addObserver(forName: NSWorkspace.didActivateApplicationNotification, object: nil, queue: .main) { [weak self] note in
            let app = note.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication
            MainActor.assumeIsolated { self?.activated(app) }
        })
        activated(NSWorkspace.shared.frontmostApplication)
    }

    /// Re-evaluates after the setting changes.
    func refresh() { update() }

    private func activated(_ app: NSRunningApplication?) {
        guard let app, app.bundleIdentifier != Bundle.main.bundleIdentifier else { return }
        foregroundApp = app
        callApp = app.bundleIdentifier.flatMap { BusyDetector.callApps[$0] }
        update()
    }

    private func update() {
        let why: String? = if !isEnabled {
            nil
        } else if screenLocked {
            "the screen is locked"
        } else if displaysAsleep {
            "the display is asleep"
        } else if let callApp {
            "you're in \(callApp)"
        } else {
            nil
        }
        reason = why
        let busy = why != nil
        guard busy != isBusy else { return }
        isBusy = busy
        onChange?(busy)
    }
}
