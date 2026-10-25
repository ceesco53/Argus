import Foundation

/// A connection held until someone decides what to do with it.
public struct ConnectionAlert: Codable, Hashable, Sendable, Identifiable {
    public var id: UUID
    public var createdAt: Date
    public var deadline: Date?
    public var process: ProcessIdentity
    public var via: ProcessIdentity?
    public var pid: Int32
    public var userID: UInt32
    public var hostname: String?
    public var address: String?
    public var port: UInt16
    public var proto: TransportProtocol
    public var direction: TrafficDirection
    /// How many connections are waiting on this answer (repeat attempts are folded in).
    public var pendingConnections: Int
    /// Set when the program's signature looks wrong.
    public var signatureWarning: String?
    /// What Argus suggests, and why.
    public var advice: ConnectionAdvice?

    public init(
        id: UUID, createdAt: Date, deadline: Date?, process: ProcessIdentity, via: ProcessIdentity?, pid: Int32, userID: UInt32,
        hostname: String?, address: String?, port: UInt16, proto: TransportProtocol, direction: TrafficDirection,
        pendingConnections: Int, signatureWarning: String?, advice: ConnectionAdvice? = nil
    ) {
        self.id = id
        self.createdAt = createdAt
        self.deadline = deadline
        self.process = process
        self.via = via
        self.pid = pid
        self.userID = userID
        self.hostname = hostname
        self.address = address
        self.port = port
        self.proto = proto
        self.direction = direction
        self.pendingConnections = pendingConnections
        self.signatureWarning = signatureWarning
        self.advice = advice
    }

    public var remoteDisplay: String { hostname ?? address ?? "unknown" }

    /// The registrable domain to offer for a domain-wide rule ("apple.com" for "www.apple.com").
    public var suggestedDomain: String? { hostname.flatMap(DomainName.registrableDomain) }
}

/// A suggested answer for an alert, built from independent signals.
public struct ConnectionAdvice: Codable, Hashable, Sendable {
    public enum Strength: Int, Codable, Sendable, Comparable {
        case weak = 1, moderate = 2, strong = 3
        public static func < (a: Strength, b: Strength) -> Bool { a.rawValue < b.rawValue }
    }

    public struct Reason: Codable, Hashable, Sendable {
        public enum Kind: String, Codable, Sendable {
            case threatList, trackerList, trackerService, firstParty, appleService, sharedInfrastructure
            case yourRules, yourHistory, otherApps, signature, incoming, localNetwork
        }

        public var kind: Kind
        /// nil when the reason is only informational.
        public var leansTo: RuleAction?
        public var strength: Strength
        public var text: String

        public init(_ kind: Kind, leansTo: RuleAction?, strength: Strength, text: String) {
            self.kind = kind
            self.leansTo = leansTo
            self.strength = strength
            self.text = text
        }
    }

    /// nil when the signals don't point either way.
    public var suggestion: RuleAction?
    public var strength: Strength
    /// Strongest first.
    public var reasons: [Reason]
    /// Set when the suggestion applies to a whole domain (e.g. a tracker's every subdomain).
    public var suggestedDomain: String?

    public init(suggestion: RuleAction?, strength: Strength, reasons: [Reason], suggestedDomain: String? = nil) {
        self.suggestion = suggestion
        self.strength = strength
        self.reasons = reasons
        self.suggestedDomain = suggestedDomain
    }

    /// The reason that best explains the suggestion.
    public var headline: String? {
        reasons.first { $0.leansTo == suggestion }?.text ?? reasons.first?.text
    }

    /// Whether this is confident enough to act on when an alert goes unanswered.
    public var isConfident: Bool { suggestion != nil && strength >= .moderate }
}

/// The answer to an alert.
public struct AlertDecision: Codable, Hashable, Sendable {
    public enum ProcessScope: String, Codable, Sendable { case thisProcess, anyProcess }

    public enum RemoteScope: Codable, Hashable, Sendable {
        case host
        case domain(String)
        case address
        case localNetwork
        case any
    }

    public enum PortScope: String, Codable, Sendable { case thisPort, anyPort }

    public enum Duration: Codable, Hashable, Sendable, CaseIterable {
        case once, untilQuit, untilRestart, minutes(Int), forever

        public static let allCases: [Duration] = [.once, .untilQuit, .minutes(15), .minutes(60), .minutes(24 * 60), .untilRestart, .forever]

        public var displayName: String {
            switch self {
            case .once: "Once"
            case .untilQuit: "Until Quit"
            case .untilRestart: "Until Restart"
            case .forever: "Forever"
            case .minutes(let m) where m % (24 * 60) == 0: m == 24 * 60 ? "For 1 Day" : "For \(m / (24 * 60)) Days"
            case .minutes(let m) where m % 60 == 0: m == 60 ? "For 1 Hour" : "For \(m / 60) Hours"
            case .minutes(let m): "For \(m) Minutes"
            }
        }
    }

    public var action: RuleAction
    public var processScope: ProcessScope
    public var remoteScope: RemoteScope
    public var portScope: PortScope
    public var duration: Duration
    public var allUsers: Bool
    /// Put the rule in the active profile only, rather than all profiles.
    public var activeProfileOnly: Bool

    public init(
        action: RuleAction, processScope: ProcessScope = .thisProcess, remoteScope: RemoteScope = .host,
        portScope: PortScope = .thisPort, duration: Duration = .forever, allUsers: Bool = true, activeProfileOnly: Bool = false
    ) {
        self.action = action
        self.processScope = processScope
        self.remoteScope = remoteScope
        self.portScope = portScope
        self.duration = duration
        self.allUsers = allUsers
        self.activeProfileOnly = activeProfileOnly
    }
}

public enum DomainName {
    /// Common multi-label public suffixes; enough to avoid offering "co.uk" as a domain.
    static let multiLabelSuffixes: Set<String> = [
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.nz", "org.nz", "co.jp", "ne.jp", "or.jp", "ac.jp", "co.kr", "or.kr",
        "com.br", "net.br", "org.br", "com.cn", "net.cn", "org.cn", "com.tw", "com.hk",
        "com.mx", "com.ar", "com.tr", "com.sg", "com.my", "co.in", "net.in", "org.in",
        "co.za", "com.ua", "co.il", "com.pl", "com.ru", "com.es", "com.vn", "com.ph",
        "cloudfront.net", "amazonaws.com", "azurewebsites.net", "herokuapp.com", "github.io",
        "appspot.com", "blogspot.com", "fastly.net", "akamaiedge.net",
    ]

    public static func registrableDomain(of host: String) -> String? {
        let labels = host.lowercased().split(separator: ".")
        guard labels.count >= 2, IPAddress(host) == nil else { return nil }
        let lastTwo = labels.suffix(2).joined(separator: ".")
        if multiLabelSuffixes.contains(lastTwo), labels.count >= 3 {
            return labels.suffix(3).joined(separator: ".")
        }
        return lastTwo
    }
}

/// Starts a PCAP capture.
public struct CaptureRequest: Codable, Hashable, Sendable {
    /// nil captures every program.
    public var processPath: String?
    /// Optional hostname/domain/address substring filter.
    public var remoteFilter: String?
    public var maxBytes: Int
    public var duration: TimeInterval?

    public init(processPath: String? = nil, remoteFilter: String? = nil, maxBytes: Int = 200 * 1024 * 1024, duration: TimeInterval? = nil) {
        self.processPath = processPath
        self.remoteFilter = remoteFilter
        self.maxBytes = maxBytes
        self.duration = duration
    }
}

public struct CaptureSession: Codable, Hashable, Sendable, Identifiable {
    public var id: UUID
    public var processPath: String?
    public var processName: String?
    public var remoteFilter: String?
    public var startedAt: Date
    public var endedAt: Date?
    public var packetCount: Int
    public var flowCount: Int
    public var fileSize: Int
    public var maxBytes: Int

    public var isActive: Bool { endedAt == nil }
    public var fileName: String {
        let stamp = ISO8601DateFormatter().string(from: startedAt).replacingOccurrences(of: ":", with: "-")
        let who = (processName ?? "All Apps").replacingOccurrences(of: "/", with: "-")
        return "Argus \(who) \(stamp).pcap"
    }
}
