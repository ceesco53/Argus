import Foundation

public enum RuleAction: String, Codable, Sendable, CaseIterable {
    case allow, deny

    public var displayName: String { self == .allow ? "Allow" : "Deny" }
    public var opposite: RuleAction { self == .allow ? .deny : .allow }
}

public enum ProcessMatch: Codable, Hashable, Sendable {
    case any
    case path(String)

    public var path: String? { if case .path(let p) = self { p } else { nil } }
}

public enum RemoteMatch: Codable, Hashable, Sendable {
    case any
    case localNetwork
    /// A single hostname, matched exactly.
    case host(String)
    /// A domain and all of its subdomains.
    case domain(String)
    /// An IP address or CIDR network.
    case address(String)

    public var displayString: String {
        switch self {
        case .any: "Any Server"
        case .localNetwork: "Local Network"
        case .host(let h): h
        case .domain(let d): "*.\(d)"
        case .address(let a): a
        }
    }

    public var kindName: String {
        switch self {
        case .any: "Any server"
        case .localNetwork: "Local network"
        case .host: "Host"
        case .domain: "Domain"
        case .address: "IP address"
        }
    }

    public var value: String {
        switch self {
        case .any, .localNetwork: ""
        case .host(let v), .domain(let v), .address(let v): v
        }
    }
}

public struct PortRange: Codable, Hashable, Sendable {
    public var lower: UInt16
    public var upper: UInt16

    public init(_ lower: UInt16, _ upper: UInt16? = nil) {
        self.lower = lower
        self.upper = max(lower, upper ?? lower)
    }

    public func contains(_ port: UInt16) -> Bool { (lower...upper).contains(port) }
    public var description: String { lower == upper ? "\(lower)" : "\(lower)-\(upper)" }
}

public enum PortMatch: Codable, Hashable, Sendable {
    case any
    case ranges([PortRange])

    public static func single(_ port: UInt16) -> PortMatch { .ranges([PortRange(port)]) }

    /// Parses "any", "443", "80, 443", or "8000-8100".
    public static func parse(_ text: String) -> PortMatch? {
        let trimmed = text.trimmingCharacters(in: .whitespaces).lowercased()
        if trimmed.isEmpty || trimmed == "any" || trimmed == "*" { return .any }
        var ranges: [PortRange] = []
        for part in trimmed.split(separator: ",") {
            let bounds = part.split(separator: "-", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            guard let lo = UInt16(bounds[0]) else { return nil }
            if bounds.count == 2 {
                guard let hi = UInt16(bounds[1]), hi >= lo else { return nil }
                ranges.append(PortRange(lo, hi))
            } else {
                ranges.append(PortRange(lo))
            }
        }
        return ranges.isEmpty ? nil : .ranges(ranges)
    }

    public func contains(_ port: UInt16) -> Bool {
        switch self {
        case .any: true
        case .ranges(let ranges): ranges.contains { $0.contains(port) }
        }
    }

    public var displayString: String {
        switch self {
        case .any: "Any Port"
        case .ranges(let ranges): ranges.map(\.description).joined(separator: ", ")
        }
    }

    public var isSinglePort: Bool {
        if case .ranges(let r) = self, r.count == 1, r[0].lower == r[0].upper { true } else { false }
    }
}

public enum ProtocolMatch: String, Codable, Sendable, CaseIterable {
    case any, tcp, udp, icmp

    public var displayName: String { self == .any ? "Any Protocol" : rawValue.uppercased() }

    public func matches(_ proto: TransportProtocol) -> Bool {
        switch self {
        case .any: true
        case .tcp: proto == .tcp
        case .udp: proto == .udp
        case .icmp: proto == .icmp || proto == .icmpv6
        }
    }
}

public enum DirectionMatch: String, Codable, Sendable, CaseIterable {
    case outgoing, incoming, both

    public var displayName: String {
        switch self {
        case .outgoing: "Outgoing"
        case .incoming: "Incoming"
        case .both: "Both Directions"
        }
    }

    public func matches(_ direction: TrafficDirection) -> Bool {
        switch self {
        case .both: true
        case .outgoing: direction == .outgoing
        case .incoming: direction == .incoming
        }
    }
}

public enum RuleExpiration: Codable, Hashable, Sendable {
    case never
    case date(Date)
    /// Ends when this particular process instance exits.
    case untilQuit(pid: Int32, startTime: UInt64)
    /// Ends at the next reboot.
    case untilRestart(bootSession: String)

    public var isTemporary: Bool { self != .never }

    public var displayString: String {
        switch self {
        case .never: "Forever"
        case .date(let d): "Until \(d.formatted(date: .abbreviated, time: .shortened))"
        case .untilQuit: "Until app quits"
        case .untilRestart: "Until restart"
        }
    }
}

public enum RuleOrigin: Codable, Hashable, Sendable {
    case user
    case alert
    case commandLine
    case defaults
    case ruleGroup(UUID)

    public var displayName: String {
        switch self {
        case .user: "Created manually"
        case .alert: "Created from alert"
        case .commandLine: "Created with argus CLI"
        case .defaults: "Default rule"
        case .ruleGroup: "From rule group"
        }
    }
}

/// A firewall rule. When several rules match a connection the most specific one wins;
/// see `Specificity` for the exact order.
public struct Rule: Codable, Hashable, Sendable, Identifiable {
    public var id: UUID
    public var action: RuleAction
    public var process: ProcessMatch
    /// When set, the process must still satisfy this code requirement or the rule is
    /// treated as a signature mismatch rather than an allow.
    public var codeRequirement: String?
    public var remote: RemoteMatch
    public var ports: PortMatch
    public var proto: ProtocolMatch
    public var direction: DirectionMatch
    /// nil applies to every user account on the Mac.
    public var userID: UInt32?
    /// nil applies in every profile.
    public var profileID: UUID?
    public var isPriority: Bool
    public var isEnabled: Bool
    public var expiration: RuleExpiration
    public var notes: String
    public var origin: RuleOrigin
    public var createdAt: Date
    public var modifiedAt: Date

    public init(
        id: UUID = UUID(),
        action: RuleAction,
        process: ProcessMatch = .any,
        codeRequirement: String? = nil,
        remote: RemoteMatch = .any,
        ports: PortMatch = .any,
        proto: ProtocolMatch = .any,
        direction: DirectionMatch = .outgoing,
        userID: UInt32? = nil,
        profileID: UUID? = nil,
        isPriority: Bool = false,
        isEnabled: Bool = true,
        expiration: RuleExpiration = .never,
        notes: String = "",
        origin: RuleOrigin = .user,
        createdAt: Date = Date()
    ) {
        self.id = id
        self.action = action
        self.process = process
        self.codeRequirement = codeRequirement
        self.remote = remote
        self.ports = ports
        self.proto = proto
        self.direction = direction
        self.userID = userID
        self.profileID = profileID
        self.isPriority = isPriority
        self.isEnabled = isEnabled
        self.expiration = expiration
        self.notes = notes
        self.origin = origin
        self.createdAt = createdAt
        self.modifiedAt = createdAt
    }

    /// Human-readable one-liner, e.g. "Allow Safari → *.apple.com on TCP 443".
    public var summary: String {
        let who = process.path.map { ProcessIdentity.defaultName(for: $0) } ?? "Any Process"
        var text = "\(action.displayName) \(who) → \(remote.displayString)"
        if ports != .any { text += " port \(ports.displayString)" }
        if proto != .any { text += " (\(proto.displayName))" }
        return text
    }

    public var isFromRuleGroup: Bool { if case .ruleGroup = origin { true } else { false } }
}

/// Ordering used to pick the winning rule. Compared field by field:
/// priority, then process-specific over any-process, then the narrower server,
/// then a narrower port and protocol, then your own rules over blocklist entries,
/// and finally deny over allow.
public struct Specificity: Comparable, Sendable, Hashable {
    public var priority: Int
    public var process: Int
    public var remote: Int
    public var port: Int
    public var proto: Int
    /// 1 for rules, 0 for blocklist entries, so an allow rule as narrow as a list entry wins.
    public var userRule: Int
    public var deny: Int

    public static func < (a: Specificity, b: Specificity) -> Bool {
        a.fields.lexicographicallyPrecedes(b.fields)
    }

    private var fields: [Int] { [priority, process, remote, port, proto, userRule, deny] }

    public init(rule: Rule) {
        priority = rule.isPriority ? 1 : 0
        process = rule.process == .any ? 0 : 1
        remote = Specificity.remoteScore(rule.remote)
        switch rule.ports {
        case .any: port = 0
        case .ranges: port = rule.ports.isSinglePort ? 2 : 1
        }
        proto = rule.proto == .any ? 0 : 1
        userRule = 1
        deny = rule.action == .deny ? 1 : 0
    }

    /// A blocklist entry.
    init(remote: Int) {
        priority = 0
        process = 0
        self.remote = remote
        port = 0
        proto = 0
        userRule = 0
        deny = 1
    }

    /// Exact host/address 1000; domains 500 + label depth; CIDR 100 + prefix; local net 10; any 0.
    static func remoteScore(_ remote: RemoteMatch) -> Int {
        switch remote {
        case .any: return 0
        case .localNetwork: return 10
        case .host: return 1000
        case .domain(let d): return 500 + d.split(separator: ".").count
        case .address(let a):
            guard let network = IPNetwork(a) else { return 100 }
            return network.isSingleAddress ? 1000 : 100 + network.prefixLength
        }
    }
}
