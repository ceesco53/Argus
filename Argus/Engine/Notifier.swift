import ArgusKit
import Foundation
import UserNotifications

/// Posts Argus's notifications and turns their buttons back into actions.
@MainActor
final class Notifier: NSObject, UNUserNotificationCenterDelegate {
    enum Action {
        case troubleshoot(appPath: String?)
        case pause(minutes: Int)
        case openDigest
        case openReview
    }

    static let blockedCategory = "argus.blocked"
    /// The same, with a way to mute it: its servers came up more than three times for the app.
    static let blockedRepeatCategory = "argus.blocked.repeat"
    static let digestCategory = "argus.digest"
    static let reviewCategory = "argus.review"

    var onAction: ((Action) -> Void)?
    private var lastBlockedNotice: [String: Date] = [:]
    private var authorized: Bool?

    func setUp() {
        let center = UNUserNotificationCenter.current()
        center.delegate = self
        let show = UNNotificationAction(identifier: "troubleshoot", title: "Show What's Blocked", options: [.foreground])
        let pause = UNNotificationAction(identifier: "pause5", title: "Pause Protection for 5 Minutes")
        let mute = UNNotificationAction(identifier: "mute", title: "Don't Notify About These Again")
        center.setNotificationCategories([
            UNNotificationCategory(identifier: Notifier.blockedCategory, actions: [show, pause], intentIdentifiers: []),
            UNNotificationCategory(identifier: Notifier.blockedRepeatCategory, actions: [show, pause, mute], intentIdentifiers: []),
            UNNotificationCategory(identifier: Notifier.digestCategory, actions: [], intentIdentifiers: []),
            UNNotificationCategory(identifier: Notifier.reviewCategory, actions: [], intentIdentifiers: []),
        ])
    }

    func post(id: String, title: String, body: String, category: String? = nil, userInfo: [String: String] = [:]) {
        guard !DebugLaunch.demo else { return }
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default
        if let category { content.categoryIdentifier = category }
        content.userInfo = userInfo
        let request = UNNotificationRequest(identifier: id, content: content, trigger: nil)
        Task {
            let center = UNUserNotificationCenter.current()
            if authorized == nil { authorized = (try? await center.requestAuthorization(options: [.alert, .sound])) ?? false }
            guard authorized == true else { return }
            try? await center.add(request)
        }
    }

    /// "Argus blocked Safari from news.google.com" for the app in use, at most every 3 minutes per app,
    /// leaving out servers the user muted for it. `app` identifies the app (its bundle identifier).
    func blocked(app: String, appName: String, appPath: String, hosts: [String]) {
        var notices = Self.notices
        let hosts = notices.unmuted(hosts, app: app)
        guard !hosts.isEmpty else { return }
        let now = Date()
        if let last = lastBlockedNotice[app], now.timeIntervalSince(last) < 180 { return }
        lastBlockedNotice[app] = now
        let offerMute = notices.record(app: app, hosts: hosts)
        Self.notices = notices
        let shown = hosts.prefix(2).joined(separator: " and ")
        let more = hosts.count > 2 ? " and \(hosts.count - 2) more" : ""
        post(id: "argus-blocked-\(app.hashValue)-\(Int(now.timeIntervalSince1970))",
             title: "Argus blocked \(appName)",
             body: "From \(shown)\(more). If \(appName) isn't working, see what's blocked.",
             category: offerMute ? Notifier.blockedRepeatCategory : Notifier.blockedCategory,
             userInfo: ["appPath": appPath, "app": app, "appName": appName, "hosts": hosts.joined(separator: "\n")])
    }

    /// What Argus remembers about these notifications, kept where Settings can show and reset it.
    static var notices: BlockedNotices {
        get { BlockedNotices(data: UserDefaults.standard.data(forKey: BlockedNotices.defaultsKey)) }
        set { UserDefaults.standard.set(newValue.data, forKey: BlockedNotices.defaultsKey) }
    }

    /// "Don't Notify About These Again": the notification's servers, for its app, from now on.
    private func mute(app: String, appName: String, hosts: [String]) {
        guard !hosts.isEmpty else { return }
        Self.notices.mute(app: app, appName: appName, hosts: hosts)
    }

    // MARK: UNUserNotificationCenterDelegate

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification) async -> UNNotificationPresentationOptions {
        [.banner, .sound]
    }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse) async {
        let category = response.notification.request.content.categoryIdentifier
        let userInfo = response.notification.request.content.userInfo
        if response.actionIdentifier == "mute" {
            guard let app = userInfo["app"] as? String, let hosts = userInfo["hosts"] as? String else { return }
            let appName = userInfo["appName"] as? String ?? app
            await MainActor.run { self.mute(app: app, appName: appName, hosts: hosts.split(separator: "\n").map(String.init)) }
            return
        }
        let appPath = userInfo["appPath"] as? String
        let action: Action? = switch (category, response.actionIdentifier) {
        case (_, "pause5"): .pause(minutes: 5)
        case (Notifier.blockedCategory, _), (Notifier.blockedRepeatCategory, _): .troubleshoot(appPath: appPath)
        case (Notifier.digestCategory, _): .openDigest
        case (Notifier.reviewCategory, _): .openReview
        default: nil
        }
        guard let action else { return }
        await MainActor.run { self.onAction?(action) }
    }
}
