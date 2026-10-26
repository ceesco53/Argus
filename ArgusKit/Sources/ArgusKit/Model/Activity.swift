import Foundation

public struct TransportProtocol: RawRepresentable, Codable, Hashable, Sendable, CustomStringConvertible {
    public var rawValue: Int32
    public init(rawValue: Int32) { self.rawValue = rawValue }

    public static let icmp = TransportProtocol(rawValue: 1)
    public static let tcp = TransportProtocol(rawValue: 6)
    public static let udp = TransportProtocol(rawValue: 17)
    public static let icmpv6 = TransportProtocol(rawValue: 58)

    public var description: String {
        switch self {
        case .tcp: "TCP"
        case .udp: "UDP"
        case .icmp: "ICMP"
        case .icmpv6: "ICMPv6"
        default: "IP proto \(rawValue)"
        }
    }
}

public enum TrafficDirection: String, Codable, Sendable, CaseIterable {
    case outgoing, incoming
}

public enum HostnameSource: String, Codable, Sendable {
    /// Reported by the system with the connection.
    case connection
    /// Learned from a DNS answer the Mac received.
    case dns
    /// Reverse DNS lookup; least trustworthy.
    case reverseLookup
    case none
}

/// Everything known about one connection attempt at decision time.
public struct FlowContext: Sendable, Hashable {
    public var process: ProcessIdentity
    /// The helper that actually opened the socket, when different from `process`.
    public var via: ProcessIdentity?
    public var pid: Int32
    public var processStartTime: UInt64?
    public var userID: UInt32
    public var auditToken: Data?
    public var hostname: String?
    public var hostnameSource: HostnameSource
    public var address: IPAddress?
    public var remotePort: UInt16
    public var localAddress: IPAddress?
    public var localPort: UInt16
    public var proto: TransportProtocol
    public var direction: TrafficDirection

    public init(
        process: ProcessIdentity, via: ProcessIdentity? = nil, pid: Int32 = 0, processStartTime: UInt64? = nil,
        userID: UInt32 = 501, auditToken: Data? = nil, hostname: String? = nil, hostnameSource: HostnameSource? = nil,
        address: IPAddress?, remotePort: UInt16, localAddress: IPAddress? = nil, localPort: UInt16 = 0,
        proto: TransportProtocol = .tcp, direction: TrafficDirection = .outgoing
    ) {
        self.process = process
        self.via = via
        self.pid = pid
        self.processStartTime = processStartTime
        self.userID = userID
        self.auditToken = auditToken
        self.hostname = hostname.flatMap { $0.isEmpty ? nil : $0.lowercased() }
        self.hostnameSource = hostnameSource ?? (self.hostname == nil ? .none : .connection)
        self.address = address
        self.remotePort = remotePort
        self.localAddress = localAddress
        self.localPort = localPort
        self.proto = proto
        self.direction = direction
    }

    /// The port rules match: the server port for outgoing traffic, our listening port for incoming.
    public var rulePort: UInt16 { direction == .incoming ? localPort : remotePort }

    public var remoteDisplay: String { hostname ?? address?.description ?? "unknown" }

    /// Groups repeated connections to the same place into one monitor row.
    public var connectionKey: String {
        "\(process.path)|\(remoteDisplay)|\(rulePort)|\(proto.rawValue)|\(direction.rawValue)"
    }
}

public enum VerdictReason: Codable, Hashable, Sendable {
    case rule(UUID)
    case blocklist(UUID)
    case mode(FilterMode)
    case alertAnswer
    case alertTimeout
    case unattended
    case appleSoftware
    case signedSoftware
    case localNetwork
    case protectionOff
    case paused
    /// Allowed quietly during the learning period, to be reviewed.
    case learning
    /// Decided without asking while the user was busy, to be reviewed.
    case deferred
    /// Argus's own traffic (same developer team).
    case argus
    case signatureMismatch(UUID)
    /// Seen by the monitor only; Argus could not intervene.
    case observed

    public var isUnapproved: Bool {
        switch self {
        case .mode, .alertTimeout, .unattended, .observed, .learning, .deferred: true
        default: false
        }
    }
}

public struct Verdict: Codable, Hashable, Sendable {
    public var action: RuleAction
    public var reason: VerdictReason
    /// False in monitor mode: the action is what Argus *would* have done.
    public var isEnforced: Bool

    public init(_ action: RuleAction, _ reason: VerdictReason, enforced: Bool = true) {
        self.action = action
        self.reason = reason
        isEnforced = enforced
    }
}

/// One row in the network monitor: repeated connections from one program to one place.
public struct ConnectionRecord: Codable, Hashable, Sendable, Identifiable {
    public var id: String
    public var processPath: String
    public var remote: String
    public var hostname: String?
    public var hostnameSource: HostnameSource
    public var addresses: [String]
    public var port: UInt16
    public var proto: TransportProtocol
    public var direction: TrafficDirection
    public var firstSeen: Date
    public var lastSeen: Date
    public var connectCount: Int
    public var allowCount: Int
    public var denyCount: Int
    public var bytesIn: UInt64
    public var bytesOut: UInt64
    public var activeFlows: Int
    public var lastVerdict: Verdict
    public var revision: UInt64

    public var totalBytes: UInt64 { bytesIn + bytesOut }
    public var isBlocked: Bool { lastVerdict.action == .deny }
}

/// Totals for one program across all its connections.
public struct ProcessRecord: Codable, Hashable, Sendable, Identifiable {
    public var identity: ProcessIdentity
    public var viaPaths: [String]
    public var userIDs: [UInt32]
    public var firstSeen: Date
    public var lastSeen: Date
    public var connectCount: Int
    public var allowCount: Int
    public var denyCount: Int
    public var unapprovedCount: Int
    public var bytesIn: UInt64
    public var bytesOut: UInt64
    public var activeFlows: Int
    public var revision: UInt64

    public var id: String { identity.path }
    public var totalBytes: UInt64 { bytesIn + bytesOut }
}

/// A single connection decision, for the live log and `argus log --follow`.
public struct FlowLogEntry: Codable, Hashable, Sendable, Identifiable {
    public var id: UInt64
    public var date: Date
    public var processPath: String
    public var processName: String
    public var remote: String
    public var address: String?
    public var port: UInt16
    public var proto: TransportProtocol
    public var direction: TrafficDirection
    public var userID: UInt32
    public var verdict: Verdict
}

public struct ActivityEvent: Codable, Hashable, Sendable, Identifiable {
    public enum Kind: String, Codable, Sendable {
        case signatureMismatch, invalidSignature, packetCapture, profileSwitched
        case ruleGroupUpdated, ruleGroupFailed, ruleExpired, captureFinished, protectionChanged, info
        case learningFinished, dataUsage
    }

    public var id: UInt64
    public var date: Date
    public var kind: Kind
    public var title: String
    public var detail: String
    public var processPath: String?

    public var isWarning: Bool {
        switch kind {
        case .signatureMismatch, .invalidSignature, .packetCapture, .ruleGroupFailed, .dataUsage: true
        default: false
        }
    }
}

public struct TrafficBucket: Codable, Hashable, Sendable {
    /// Seconds since 1970 at the start of the bucket.
    public var start: Int64
    public var bytesIn: UInt64
    public var bytesOut: UInt64

    public init(start: Int64, bytesIn: UInt64, bytesOut: UInt64) {
        self.start = start
        self.bytesIn = bytesIn
        self.bytesOut = bytesOut
    }

    public var date: Date { Date(timeIntervalSince1970: TimeInterval(start)) }
    public var total: UInt64 { bytesIn + bytesOut }
}

public enum TrafficResolution: String, Codable, Sendable {
    case second, minute, hour

    public var seconds: Int64 {
        switch self {
        case .second: 1
        case .minute: 60
        case .hour: 3600
        }
    }
}

public struct TrafficQuery: Codable, Hashable, Sendable {
    public var processPath: String?
    public var resolution: TrafficResolution
    public var since: Date

    public init(processPath: String? = nil, resolution: TrafficResolution, since: Date) {
        self.processPath = processPath
        self.resolution = resolution
        self.since = since
    }
}

public struct DailyCounters: Codable, Hashable, Sendable {
    public var day: String
    public var connections: Int = 0
    public var blocked: Int = 0
    public var blockedByLists: Int = 0
    public var bytesIn: UInt64 = 0
    public var bytesOut: UInt64 = 0
    /// Blocked connections by registrable domain, for the weekly digest.
    public var blockedDomains: [String: Int] = [:]
    /// Blocked connections by program name.
    public var blockedApps: [String: Int] = [:]
    /// Programs that used the network for the first time that day.
    public var newApps: [String] = []

    public init(day: String) { self.day = day }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        day = try c.decode(String.self, forKey: .day)
        connections = try c.decodeIfPresent(Int.self, forKey: .connections) ?? 0
        blocked = try c.decodeIfPresent(Int.self, forKey: .blocked) ?? 0
        blockedByLists = try c.decodeIfPresent(Int.self, forKey: .blockedByLists) ?? 0
        bytesIn = try c.decodeIfPresent(UInt64.self, forKey: .bytesIn) ?? 0
        bytesOut = try c.decodeIfPresent(UInt64.self, forKey: .bytesOut) ?? 0
        blockedDomains = try c.decodeIfPresent([String: Int].self, forKey: .blockedDomains) ?? [:]
        blockedApps = try c.decodeIfPresent([String: Int].self, forKey: .blockedApps) ?? [:]
        newApps = try c.decodeIfPresent([String].self, forKey: .newApps) ?? []
    }

    public static func dayKey(for date: Date) -> String {
        let c = Calendar.current.dateComponents([.year, .month, .day], from: date)
        return String(format: "%04d-%02d-%02d", c.year ?? 0, c.month ?? 0, c.day ?? 0)
    }
}

public struct Rate: Codable, Hashable, Sendable {
    public var bytesInPerSecond: Double
    public var bytesOutPerSecond: Double

    public init(bytesInPerSecond: Double, bytesOutPerSecond: Double) {
        self.bytesInPerSecond = bytesInPerSecond
        self.bytesOutPerSecond = bytesOutPerSecond
    }

    public static let zero = Rate(bytesInPerSecond: 0, bytesOutPerSecond: 0)
    public var total: Double { bytesInPerSecond + bytesOutPerSecond }
}

/// Activity that changed since a revision. A full snapshot replaces the client's copy.
public struct ActivitySnapshot: Codable, Sendable {
    public var revision: UInt64
    public var isFull: Bool
    public var processes: [ProcessRecord]
    public var connections: [ConnectionRecord]
    public var log: [FlowLogEntry]
    public var events: [ActivityEvent]
    public var today: DailyCounters
    /// Global per-second traffic for the last two minutes.
    public var recentTraffic: [TrafficBucket]
    /// Current rates for programs that moved data in the last few seconds.
    public var processRates: [String: Rate]
    public var bpfUsers: [BPFUser]
}

/// A program holding a Berkeley Packet Filter device open, i.e. able to read raw traffic.
public struct BPFUser: Codable, Hashable, Sendable, Identifiable {
    public var pid: Int32
    public var path: String
    public var name: String
    public var device: String
    public var userID: UInt32
    public var firstSeen: Date

    public var id: String { "\(pid):\(device)" }

    public init(pid: Int32, path: String, name: String, device: String, userID: UInt32, firstSeen: Date = Date()) {
        self.pid = pid
        self.path = path
        self.name = name
        self.device = device
        self.userID = userID
        self.firstSeen = firstSeen
    }
}
