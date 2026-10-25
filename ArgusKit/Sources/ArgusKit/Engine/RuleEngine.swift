import Foundation

/// The rule that decided a connection.
public struct RuleMatch: Sendable, Hashable {
    public var action: RuleAction
    public var rule: Rule?
    /// Set when a blocklist entry (not a rule) matched.
    public var blocklistID: UUID?
    public var specificity: Specificity

    public var reason: VerdictReason {
        if let rule { return .rule(rule.id) }
        return .blocklist(blocklistID ?? UUID())
    }
}

/// Rules indexed for fast evaluation. Rebuilt whenever rules, profiles or groups change.
public struct CompiledRuleSet: Sendable {
    struct Entry: Sendable {
        let rule: Rule
        let specificity: Specificity
        let network: IPNetwork?
    }

    private var anyProcess: [Entry] = []
    private var byPath: [String: [Entry]] = [:]
    private var blocklists: [(id: UUID, list: CompiledBlocklist)] = []

    public init() {}

    /// - Parameters:
    ///   - rules: user rules plus the rules of enabled rule groups.
    ///   - activeProfile: rules bound to other profiles are left out.
    public init(rules: [Rule], activeProfile: UUID?, blocklists: [(UUID, CompiledBlocklist)], now: Date = Date()) {
        for rule in rules where rule.isEnabled {
            if let profile = rule.profileID, profile != activeProfile { continue }
            if case .date(let end) = rule.expiration, end <= now { continue }
            var network: IPNetwork?
            if case .address(let text) = rule.remote {
                guard let parsed = IPNetwork(text) else { continue }
                network = parsed
            }
            let entry = Entry(rule: rule, specificity: Specificity(rule: rule), network: network)
            switch rule.process {
            case .any: anyProcess.append(entry)
            case .path(let path): byPath[path, default: []].append(entry)
            }
        }
        self.blocklists = blocklists.map { (id: $0.0, list: $0.1) }
    }

    public func evaluate(_ flow: FlowContext) -> RuleMatch? {
        var best: RuleMatch?
        func consider(_ candidate: RuleMatch) {
            if best == nil || best!.specificity < candidate.specificity { best = candidate }
        }
        for entry in byPath[flow.process.path] ?? [] where CompiledRuleSet.matches(entry, flow) {
            consider(RuleMatch(action: entry.rule.action, rule: entry.rule, specificity: entry.specificity))
        }
        for entry in anyProcess where CompiledRuleSet.matches(entry, flow) {
            consider(RuleMatch(action: entry.rule.action, rule: entry.rule, specificity: entry.specificity))
        }
        // Blocklists act like "deny any process" rules, so a process-specific or priority
        // rule always outranks them and the lookup can be skipped.
        let blocklistCanWin = best.map { $0.specificity.priority == 0 && $0.specificity.process == 0 } ?? true
        if flow.direction == .outgoing, blocklistCanWin {
            for (id, list) in blocklists {
                if let host = flow.hostname, let match = list.domains.match(host) {
                    let score: Int = switch match {
                    case .exact: 1000
                    case .suffix(let domain): 500 + domain.split(separator: ".").count
                    }
                    consider(RuleMatch(action: .deny, blocklistID: id, specificity: Specificity(remote: score)))
                }
                // IP lists describe the internet. Lists made for servers (e.g. FireHOL) also name
                // the private ranges, which on a Mac would cut off the router, DNS server and printer.
                if let address = flow.address, !address.isLocalNetwork, list.addresses.contains(address) {
                    consider(RuleMatch(action: .deny, blocklistID: id, specificity: Specificity(remote: 100)))
                }
            }
        }
        return best
    }

    /// Enabled rules that name this program, most specific first.
    public func rules(forProcessPath path: String) -> [Rule] {
        (byPath[path] ?? []).sorted { $0.specificity > $1.specificity }.map(\.rule)
    }

    static func matches(_ entry: Entry, _ flow: FlowContext) -> Bool {
        let rule = entry.rule
        if let uid = rule.userID, uid != flow.userID { return false }
        guard rule.direction.matches(flow.direction), rule.proto.matches(flow.proto), rule.ports.contains(flow.rulePort) else {
            return false
        }
        switch rule.remote {
        case .any:
            return true
        case .localNetwork:
            return flow.address?.isLocalNetwork ?? false
        case .host(let host):
            if let hostname = flow.hostname, hostname == host.lowercased() { return true }
            if let address = flow.address, let ruleAddress = IPAddress(host) { return address == ruleAddress }
            return false
        case .domain(let domain):
            guard let hostname = flow.hostname else { return false }
            let d = domain.lowercased()
            return hostname == d || hostname.hasSuffix("." + d)
        case .address:
            guard let address = flow.address, let network = entry.network else { return false }
            return network.contains(address)
        }
    }
}
