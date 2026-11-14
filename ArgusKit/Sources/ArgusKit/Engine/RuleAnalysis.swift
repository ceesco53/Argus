import Foundation

public enum RuleIssue: Hashable, Sendable {
    /// Matches exactly what an older rule matches, with the same action: it does nothing.
    case duplicate(of: UUID)
    /// Matches exactly what a deny rule matches, but allows: deny wins ties, so it never applies.
    case overruled(by: UUID)
    /// Matches only connections a broader rule for the same program already decides the same way.
    case covered(by: UUID)

    public var explanation: String {
        switch self {
        case .duplicate: "Duplicate: another rule already does exactly this."
        case .overruled: "Never applies: a deny rule matches exactly the same connections, and deny wins ties."
        case .covered: "Not needed: a broader rule for this program already decides these connections the same way."
        }
    }

    /// Whether removing the rule changes nothing.
    public var isRedundant: Bool {
        switch self {
        case .duplicate, .covered: true
        case .overruled: false
        }
    }
}

/// Finds rules that can't make a difference.
public enum RuleAnalysis {
    /// - Parameter others: rules from rule groups: never flagged themselves, but one of them can
    ///   be what a rule is needed against.
    public static func issues(in rules: [Rule], alongside others: [Rule] = []) -> [UUID: RuleIssue] {
        var issues = exactIssues(in: rules)
        for (id, broader) in covered(in: rules, alongside: others) where issues[id] == nil { issues[id] = .covered(by: broader) }
        return issues
    }

    private static func exactIssues(in rules: [Rule]) -> [UUID: RuleIssue] {
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

    // MARK: Rules a broader rule covers

    /// Alert answers a broader rule takes the place of: rules made from alerts, one server at a
    /// time, that `broader` makes unnecessary. A game's hundreds of relays become its one rule.
    /// Rules written or annotated by hand stay; Rules points those out instead.
    /// - Parameter others: rules from rule groups, one of which may be what an answer is needed
    ///   against. Only read when the app has earlier answers at all.
    public static func answersReplaced(by broader: Rule, in rules: [Rule], alongside others: @autoclosure () -> [Rule] = []) -> [UUID] {
        guard broader.process != .any, let broad = Shape(broader) else { return [] }
        let answers = rules.filter { $0.id != broader.id && $0.process == broader.process && $0.origin == .alert && $0.notes.isEmpty }
        guard !answers.isEmpty else { return [] }
        let opposing = opposingShapes(rules + others()).filter { $0.rule.action != broader.action }
        return answers.compactMap(Shape.init).filter { makesUnnecessary(broad, $0, opposing: opposing) }.map(\.rule.id)
    }

    /// The rules that can rank between two rules for the same program: other rules for a program.
    /// One for every program ranks below them both, or (with priority) above them both.
    private static func opposingShapes(_ rules: [Rule]) -> [Shape] {
        rules.filter { $0.isEnabled && $0.process != .any }.compactMap(Shape.init)
    }

    /// Rules a less specific rule for the same program makes unnecessary, each with the rule that does.
    private static func covered(in rules: [Rule], alongside others: [Rule]) -> [UUID: UUID] {
        let shapes = opposingShapes(rules)
        let opposing = shapes + opposingShapes(others)
        var result: [UUID: UUID] = [:]
        for (_, group) in Dictionary(grouping: shapes, by: \.rule.process) where group.count > 1 {
            let ordered = group.sorted { $0.specificity < $1.specificity }
            // Rules of one specificity can't cover each other, so each looks only at the tiers below
            // its own. A program with hundreds of single-server rules is one tier.
            var tierStart = 0
            for index in ordered.indices {
                if index > 0, ordered[index - 1].specificity < ordered[index].specificity { tierStart = index }
                guard let broad = ordered[..<tierStart].first(where: { makesUnnecessary($0, ordered[index], opposing: opposing) }) else { continue }
                result[ordered[index].rule.id] = broad.rule.id
            }
        }
        return result
    }

    /// Whether `narrow` can go because `broad` decides everything it matches the same way, and
    /// would be the rule to decide it: no rule that says the opposite ranks between the two.
    private static func makesUnnecessary(_ broad: Shape, _ narrow: Shape, opposing: [Shape]) -> Bool {
        let b = broad.rule, a = narrow.rule
        guard b.isEnabled, a.isEnabled, b.action == a.action, b.process == a.process, b.isPriority == a.isPriority,
              b.codeRequirement == a.codeRequirement, b.expiration == .never, broad.covers(narrow) else { return false }
        return !opposing.contains { other in
            other.rule.action != a.action && broad.specificity < other.specificity && other.specificity < narrow.specificity
                && other.appliesToProgram(of: narrow) && other.overlaps(narrow)
        }
    }

    /// What a rule matches, read once so pairs of rules compare cheaply.
    private struct Shape {
        enum Remote {
            case any, localNetwork
            case name(String), domain(String)
            case network(IPNetwork)
        }

        let rule: Rule
        let remote: Remote
        let specificity: Specificity

        /// nil for a rule the engine can't apply either (an address that isn't one).
        init?(_ rule: Rule) {
            switch rule.remote {
            case .any: remote = .any
            case .localNetwork: remote = .localNetwork
            case .host(let host):
                remote = IPAddress(host).map { .network(IPNetwork(address: $0, prefixLength: $0.isIPv4 ? 32 : 128)) } ?? .name(host.lowercased())
            case .domain(let domain): remote = .domain(domain.lowercased())
            case .address(let text):
                guard let network = IPNetwork(text) else { return nil }
                remote = .network(network)
            }
            self.rule = rule
            specificity = Specificity(rule: rule)
        }

        /// Every connection `other` matches, this rule matches too.
        func covers(_ other: Shape) -> Bool {
            let mine = rule, theirs = other.rule
            guard mine.userID == nil || mine.userID == theirs.userID, mine.profileID == nil || mine.profileID == theirs.profileID,
                  mine.direction == .both || mine.direction == theirs.direction, mine.proto == .any || mine.proto == theirs.proto,
                  mine.ports.covers(theirs.ports) else { return false }
            switch (remote, other.remote) {
            case (.any, _), (.localNetwork, .localNetwork):
                return true
            case (.name(let host), .name(let name)):
                return host == name
            case (.domain(let domain), .name(let name)), (.domain(let domain), .domain(let name)):
                return name == domain || name.hasSuffix("." + domain)
            case (.network(let network), .network(let inner)):
                return network.prefixLength <= inner.prefixLength && network.contains(inner.address)
            default:
                return false
            }
        }

        /// Whether some connection could match both rules. Says yes when it can't tell.
        func overlaps(_ other: Shape) -> Bool {
            let mine = rule, theirs = other.rule
            guard mine.userID == nil || theirs.userID == nil || mine.userID == theirs.userID,
                  mine.profileID == nil || theirs.profileID == nil || mine.profileID == theirs.profileID,
                  mine.direction == .both || theirs.direction == .both || mine.direction == theirs.direction,
                  mine.proto == .any || theirs.proto == .any || mine.proto == theirs.proto,
                  mine.ports.overlaps(theirs.ports) else { return false }
            switch (remote, other.remote) {
            case (.name(let one), .name(let two)):
                return one == two
            case (.name(let name), .domain(let domain)), (.domain(let domain), .name(let name)):
                return name == domain || name.hasSuffix("." + domain)
            case (.domain(let one), .domain(let two)):
                return one == two || one.hasSuffix("." + two) || two.hasSuffix("." + one)
            case (.network(let one), .network(let two)):
                return one.contains(two.address) || two.contains(one.address)
            default:
                return true // a connection to a name has an address too, and either can be local
            }
        }

        /// Whether this rule can decide connections of `other`'s program: it's for any program, for
        /// that one, or for a helper whose connections Argus files under it (WebKit's networking
        /// process, a program inside the same app bundle).
        func appliesToProgram(of other: Shape) -> Bool {
            guard let path = rule.process.path, let theirs = other.rule.process.path, path != theirs else { return true }
            if (path as NSString).lastPathComponent == "com.apple.WebKit.Networking" { return true }
            guard let app = ProcessIdentity.outermostAppBundle(for: path) else { return false }
            return app == ProcessIdentity.outermostAppBundle(for: theirs)
        }
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
