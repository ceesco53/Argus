import Foundation

/// What Argus remembers about its "Argus blocked Safari" notifications: how often each server came
/// up for each app, and which the user muted after seeing them often enough. An app is identified
/// by `app` (its bundle identifier, else its path).
public struct BlockedNotices: Codable, Sendable, Equatable {
    /// A server the user asked not to be notified about again for one app.
    public struct Muted: Codable, Sendable, Hashable, Identifiable {
        public var app: String
        public var appName: String
        public var host: String
        public var date: Date

        public var id: String { BlockedNotices.key(app: app, host: host) }
    }

    /// Muting is offered once a server has come up more than this many times for an app.
    public static let muteOfferedAfter = 3
    /// Counts kept before starting over, so they don't grow forever.
    static let maxCounts = 5000

    private var counts: [String: Int] = [:]
    public private(set) var muted: [Muted] = []

    public init() {}

    static func key(app: String, host: String) -> String { app + "\n" + host.lowercased() }

    public func isMuted(app: String, host: String) -> Bool {
        let key = Self.key(app: app, host: host)
        return muted.contains { $0.id == key }
    }

    /// The hosts a notification about `app` should still mention.
    public func unmuted(_ hosts: [String], app: String) -> [String] {
        hosts.filter { !isMuted(app: app, host: $0) }
    }

    /// How many notifications mentioned this server for this app.
    public func count(app: String, host: String) -> Int { counts[Self.key(app: app, host: host)] ?? 0 }

    /// Notes a notification about these servers. True when it may offer muting them: each has
    /// now come up more than `muteOfferedAfter` times.
    @discardableResult
    public mutating func record(app: String, hosts: [String]) -> Bool {
        guard !hosts.isEmpty else { return false }
        if counts.count > Self.maxCounts { counts = [:] }
        for host in Set(hosts.map { $0.lowercased() }) { counts[Self.key(app: app, host: host), default: 0] += 1 }
        return hosts.allSatisfy { count(app: app, host: $0) > Self.muteOfferedAfter }
    }

    public mutating func mute(app: String, appName: String, hosts: [String], at date: Date = Date()) {
        for host in hosts where !isMuted(app: app, host: host) {
            muted.append(Muted(app: app, appName: appName, host: host.lowercased(), date: date))
        }
    }

    public mutating func unmute(_ notice: Muted) { muted.removeAll { $0.id == notice.id } }

    public mutating func unmuteAll() { muted = [] }
}

extension BlockedNotices {
    /// Where the app keeps them.
    public static let defaultsKey = "blockedNotices"

    public init(data: Data?) {
        self = data.flatMap { try? JSONDecoder().decode(BlockedNotices.self, from: $0) } ?? BlockedNotices()
    }

    public var data: Data { (try? JSONEncoder().encode(self)) ?? Data() }
}
