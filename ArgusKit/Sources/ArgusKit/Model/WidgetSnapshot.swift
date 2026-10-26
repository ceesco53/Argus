import Foundation

/// What the widgets and Control Center controls show, written by the app into the shared
/// app group container (widgets can't talk to the engine on every refresh).
public struct WidgetSnapshot: Codable, Sendable, Equatable {
    public enum Status: String, Codable, Sendable {
        case watching, paused, off, learning, monitor
    }

    public var status: Status
    public var pausedUntil: Date?
    public var mode: FilterMode
    public var profileName: String?
    public var connectionsToday: Int
    public var blockedToday: Int
    public var blockedByListsToday: Int
    public var updated: Date

    public init(status: Status, pausedUntil: Date?, mode: FilterMode, profileName: String?, connectionsToday: Int,
                blockedToday: Int, blockedByListsToday: Int, updated: Date = Date()) {
        self.status = status
        self.pausedUntil = pausedUntil
        self.mode = mode
        self.profileName = profileName
        self.connectionsToday = connectionsToday
        self.blockedToday = blockedToday
        self.blockedByListsToday = blockedByListsToday
        self.updated = updated
    }

    /// Info.plist key holding the app group shared by the app and its widgets.
    public static let appGroupInfoKey = "ArgusAppGroup"

    static var fileURL: URL? {
        guard let group = Bundle.main.object(forInfoDictionaryKey: appGroupInfoKey) as? String, !group.hasPrefix("."),
              let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group) else { return nil }
        return container.appendingPathComponent("widget-snapshot.json")
    }

    public static func load() -> WidgetSnapshot? {
        guard let url = fileURL, let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode(WidgetSnapshot.self, from: data)
    }

    /// Returns false when there's no shared container (unsigned builds).
    @discardableResult
    public func save() -> Bool {
        guard let url = WidgetSnapshot.fileURL, let data = try? JSONEncoder().encode(self) else { return false }
        return (try? data.write(to: url, options: .atomic)) != nil
    }

    /// The same apart from when it was written.
    public func matches(_ other: WidgetSnapshot) -> Bool {
        var a = self, b = other
        a.updated = .distantPast
        b.updated = .distantPast
        return a == b
    }
}
