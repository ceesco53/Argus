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
        center.setNotificationCategories([
            UNNotificationCategory(identifier: Notifier.blockedCategory, actions: [show, pause], intentIdentifiers: []),
            UNNotificationCategory(identifier: Notifier.digestCategory, actions: [], intentIdentifiers: []),
            UNNotificationCategory(identifier: Notifier.reviewCategory, actions: [], intentIdentifiers: []),
        ])
    }

    func post(id: String, title: String, body: String, category: String? = nil, userInfo: [String: String] = [:]) {
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

    /// "Argus blocked Safari from news.google.com" for the app in use, at most every 3 minutes per app.
    func blocked(appName: String, appPath: String, hosts: [String]) {
        let now = Date()
        if let last = lastBlockedNotice[appPath], now.timeIntervalSince(last) < 180 { return }
        lastBlockedNotice[appPath] = now
        let shown = hosts.prefix(2).joined(separator: " and ")
        let more = hosts.count > 2 ? " and \(hosts.count - 2) more" : ""
        post(id: "argus-blocked-\(appPath.hashValue)-\(Int(now.timeIntervalSince1970))",
             title: "Argus blocked \(appName)",
             body: "From \(shown)\(more). If \(appName) isn't working, see what's blocked.",
             category: Notifier.blockedCategory, userInfo: ["appPath": appPath])
    }

    // MARK: UNUserNotificationCenterDelegate

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification) async -> UNNotificationPresentationOptions {
        [.banner, .sound]
    }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse) async {
        let category = response.notification.request.content.categoryIdentifier
        let appPath = response.notification.request.content.userInfo["appPath"] as? String
        let action: Action? = switch (category, response.actionIdentifier) {
        case (_, "pause5"): .pause(minutes: 5)
        case (Notifier.blockedCategory, _): .troubleshoot(appPath: appPath)
        case (Notifier.digestCategory, _): .openDigest
        case (Notifier.reviewCategory, _): .openReview
        default: nil
        }
        guard let action else { return }
        await MainActor.run { self.onAction?(action) }
    }
}
