import Foundation

public enum RuleIssue: Hashable, Sendable {
    /// Matches exactly what an older rule matches, with the same action: it does nothing.
    case duplicate(of: UUID)
    /// Matches exactly what a deny rule matches, but allows: deny wins ties, so it never applies.
    case overruled(by: UUID)

    public var explanation: String {
        switch self {
        case .duplicate: "Duplicate: another rule already does exactly this."
        case .overruled: "Never applies: a deny rule matches exactly the same connections, and deny wins ties."
        }
    }
}

/// Finds rules that can't make a difference.
public enum RuleAnalysis {
    public static func issues(in rules: [Rule]) -> [UUID: RuleIssue] {
        var firstByKey: [MatchKey: Rule] = [:]
        var denyByKey: [MatchKey: Rule] = [:]
        var issues: [UUID: RuleIssue] = [:]
        for rule in rules.filter(\.isEnabled).sorted(by: { $0.createdAt < $1.createdAt }) {
            let key = MatchKey(rule)
            if let earlier = firstByKey[key], earlier.action == rule.action {
                issues[rule.id] = .duplicate(of: earlier.id)
            } else if firstByKey[key] == nil {
                firstByKey[key] = rule
            }
            if rule.action == .deny, denyByKey[key] == nil { denyByKey[key] = rule }
        }
        for rule in rules where rule.isEnabled && rule.action == .allow && issues[rule.id] == nil {
            if let deny = denyByKey[MatchKey(rule)] { issues[rule.id] = .overruled(by: deny.id) }
        }
        return issues
    }

    /// `incoming` without the rules that would duplicate an enabled rule of `existing` or each other.
    public static func withoutDuplicates(_ incoming: [Rule], of existing: [Rule]) -> [Rule] {
        var seen = Set(existing.filter(\.isEnabled).map(Effect.init))
        return incoming.filter { seen.insert(Effect($0)).inserted }
    }

    private struct Effect: Hashable {
        let key: MatchKey
        let action: RuleAction

        init(_ rule: Rule) {
            key = MatchKey(rule)
            action = rule.action
        }
    }

    /// Everything that decides which connections a rule matches and how it ranks.
    private struct MatchKey: Hashable {
        let process: ProcessMatch
        let remote: String
        let ports: PortMatch
        let proto: ProtocolMatch
        let direction: DirectionMatch
        let userID: UInt32?
        let profileID: UUID?
        let isPriority: Bool

        init(_ rule: Rule) {
            process = rule.process
            remote = "\(rule.remote.kindName)|\(rule.remote.value.lowercased())"
            ports = rule.ports
            proto = rule.proto
            direction = rule.direction
            userID = rule.userID
            profileID = rule.profileID
            isPriority = rule.isPriority
        }
    }
}
