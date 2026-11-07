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

    /// Rules written for helpers inside an app's bundle, rewritten for the app itself.
    ///
    /// Argus files a helper's connections under the app that runs it, and the helper's location
    /// can change with every update of the app (Chrome keeps its helpers in a folder named after
    /// its version), so a rule for the app keeps working where a rule for the helper stops.
    /// - Parameters:
    ///   - app: the app's own program for an app bundle path; nil when it isn't installed.
    ///   - seenFiledUnderApp: helpers whose connections Argus has already filed under their app.
    ///     Helpers in the bundle's Frameworks or XPCServices are always started by the app;
    ///     anything else (a login item, say) may run on its own, and only moves once it was seen.
    public static func movingHelperRules(
        _ rules: [Rule], app: (String) -> ProcessIdentity?, seenFiledUnderApp: Set<String> = []
    ) -> HelperRuleMove {
        var move = HelperRuleMove()
        var candidates: [Rule] = []
        var owners: [String: ProcessIdentity?] = [:]
        func owner(of bundle: String) -> ProcessIdentity? {
            if let known = owners[bundle] { return known }
            let found = app(bundle)
            owners[bundle] = found
            return found
        }
        for rule in rules.sorted(by: { $0.createdAt < $1.createdAt }) {
            guard !rule.isFromRuleGroup, let path = rule.process.path, ProcessIdentity.isBundledHelper(path),
                  let bundle = ProcessIdentity.outermostAppBundle(for: path) else { continue }
            if case .untilQuit = rule.expiration { continue } // tied to the helper's own process
            let startedByApp = seenFiledUnderApp.contains(path) || path.contains("/Contents/Frameworks/") || path.contains("/Contents/XPCServices/")
            guard startedByApp, let owner = owner(of: bundle), owner.path != path else { continue }
            // A rule pinned to the helper's signature must stay pinned, to the app's.
            if rule.codeRequirement != nil, owner.designatedRequirement == nil { continue }
            var moved = rule
            moved.process = .path(owner.path)
            if rule.codeRequirement != nil { moved.codeRequirement = owner.designatedRequirement }
            let note = "Moved from \(ProcessIdentity.defaultName(for: path))"
            moved.notes = rule.notes.isEmpty ? note : "\(rule.notes) · \(note)"
            candidates.append(moved)
            move.apps[owner.name, default: 0] += 1
        }
        let movingIDs = Set(candidates.map(\.id))
        var seen = Set(rules.filter { $0.isEnabled && !movingIDs.contains($0.id) }.map(Effect.init))
        for rule in candidates {
            if rule.isEnabled, !seen.insert(Effect(rule)).inserted {
                move.duplicates.append(rule.id)
            } else {
                move.moved.append(rule)
            }
        }
        return move
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

/// Rules for apps' helpers, ready to become rules for the apps themselves.
public struct HelperRuleMove: Sendable, Equatable {
    /// The rewritten rules, with their original IDs.
    public var moved: [Rule] = []
    /// Rules that, once moved, would only repeat another rule: they're removed instead.
    public var duplicates: [UUID] = []
    /// How many rules each app gets, by the app's name.
    public var apps: [String: Int] = [:]

    public init() {}

    public var isEmpty: Bool { moved.isEmpty && duplicates.isEmpty }
    public var count: Int { moved.count + duplicates.count }
}
