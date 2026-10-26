import Foundation

/// One change to the configuration, as shown in Recent Changes and offered for undo.
public struct ChangeRecord: Codable, Hashable, Sendable, Identifiable {
    public var id: UInt64
    public var date: Date
    public var summary: String
    public var isUndone: Bool
}

/// "What would Argus do if this app connected to that host?"
public struct ConnectionTest: Codable, Hashable, Sendable {
    /// nil asks about any app (only rules for every program apply).
    public var processPath: String?
    public var host: String
    public var port: UInt16
    public var proto: TransportProtocol
    public var direction: TrafficDirection

    public init(processPath: String?, host: String, port: UInt16 = 443, proto: TransportProtocol = .tcp, direction: TrafficDirection = .outgoing) {
        self.processPath = processPath
        self.host = host
        self.port = port
        self.proto = proto
        self.direction = direction
    }
}

public struct ConnectionTestResult: Codable, Hashable, Sendable {
    /// nil means Argus would ask.
    public var verdict: Verdict?
    public var explanation: String
    public var ruleID: UUID?
    public var blocklistName: String?
    public var advice: ConnectionAdvice?
    public var processName: String
}

public struct NamedCount: Codable, Hashable, Sendable, Identifiable {
    public var name: String
    public var count: Int
    public var id: String { name }
}

/// A summary of recent days, for the weekly report.
public struct Digest: Codable, Sendable {
    public var days: [DailyCounters]
    public var connections: Int
    public var blocked: Int
    public var blockedByLists: Int
    public var bytesIn: UInt64
    public var bytesOut: UInt64
    public var topBlockedDomains: [NamedCount]
    public var topBlockedApps: [NamedCount]
    public var newApps: [String]

    public init(days: [DailyCounters]) {
        self.days = days
        connections = days.reduce(0) { $0 + $1.connections }
        blocked = days.reduce(0) { $0 + $1.blocked }
        blockedByLists = days.reduce(0) { $0 + $1.blockedByLists }
        bytesIn = days.reduce(0) { $0 + $1.bytesIn }
        bytesOut = days.reduce(0) { $0 + $1.bytesOut }
        func top(_ counts: [String: Int]) -> [NamedCount] {
            counts.sorted { $0.value > $1.value || ($0.value == $1.value && $0.key < $1.key) }.prefix(8).map { NamedCount(name: $0.key, count: $0.value) }
        }
        topBlockedDomains = top(days.reduce(into: [:]) { totals, day in totals.merge(day.blockedDomains, uniquingKeysWith: +) })
        topBlockedApps = top(days.reduce(into: [:]) { totals, day in totals.merge(day.blockedApps, uniquingKeysWith: +) })
        var seen = Set<String>()
        newApps = days.flatMap(\.newApps).filter { seen.insert($0).inserted }
    }
}
