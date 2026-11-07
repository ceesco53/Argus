import Foundation

/// A choice about one ad domain: block it, allow it, or (nil) leave it to the lists.
public struct AdDomainDecision: Codable, Hashable, Sendable {
    /// A host, or a domain and its subdomains.
    public var remote: RemoteMatch
    public var action: RuleAction?

    public init(_ remote: RemoteMatch, _ action: RuleAction?) {
        self.remote = remote
        self.action = action
    }

    /// The same server however it was typed: "host|ads.example.com", "domain|example.com".
    var key: String { "\(remote.kindName)|\(remote.value.lowercased())" }
}

/// Services that detect ad blockers: when their servers are blocked, sites using them refuse to
/// load or hide their content ("please allow ads"), and when they're let through, they serve the
/// ads themselves. Neither choice gives both a working page and no ads, so Argus says so instead
/// of suggesting a block.
///
/// Kept short and limited to servers known to belong to these services: html-load.com,
/// html-load.cc and content-loader.com are Ad-Shield's, and its block page sends people to
/// error-report.com; upapi.net is Blockthrough's.
public enum AntiAdblock {
    public static let services: [String: String] = [
        "html-load.com": "Ad-Shield",
        "html-load.cc": "Ad-Shield",
        "content-loader.com": "Ad-Shield",
        "error-report.com": "Ad-Shield",
        "upapi.net": "Blockthrough",
    ]

    /// The service a host belongs to, including its subdomains (fb.html-load.com).
    public static func service(for host: String) -> String? {
        var name = Substring(host.lowercased())
        while true {
            if let service = services[String(name)] { return service }
            guard let dot = name.firstIndex(of: ".") else { return nil }
            name = name[name.index(after: dot)...]
        }
    }
}

/// What kind of server a host is, as far as Argus can tell.
public enum HostCategory: String, Codable, Sendable {
    /// Advertising, tracking or analytics.
    case advertising
    /// An anti-adblock service: blocking it can make sites refuse to load.
    case antiAdblock
    /// Malware, phishing or scam infrastructure.
    case threat
}

public struct HostInfo: Codable, Hashable, Sendable {
    public var host: String
    public var category: HostCategory?
    /// Who says so: a list's name, or the service's ("Google's DoubleClick").
    public var source: String?

    public init(host: String, category: HostCategory?, source: String?) {
        self.host = host
        self.category = category
        self.source = source
    }
}

extension RuleGroup {
    /// Applies decisions to Ad Domains' rules: each replaces any earlier decision for the same server.
    mutating func apply(_ decisions: [AdDomainDecision], now: Date) throws {
        for decision in decisions {
            let remote: RemoteMatch
            switch decision.remote {
            case .host(let value):
                guard let host = DomainSet.normalize(value) else { throw ArgusError.invalid("“\(value)” isn't a server name.") }
                remote = .host(host)
            case .domain(let value):
                guard let domain = DomainSet.normalize(value) else { throw ArgusError.invalid("“\(value)” isn't a domain.") }
                remote = .domain(domain)
            default:
                throw ArgusError.invalid("Ad Domains hold servers and domains only.")
            }
            let key = AdDomainDecision(remote, nil).key
            rules.removeAll { AdDomainDecision($0.remote, nil).key == key }
            if let action = decision.action {
                rules.append(Rule(action: action, remote: remote, origin: .ruleGroup(id), createdAt: now))
            }
        }
        modifiedAt = now
    }

    /// Ad Domains' rules as the engine wants them, whatever a client sent.
    mutating func normalizeAdDomainRules() {
        rules = rules.compactMap { rule in
            switch rule.remote {
            case .host, .domain: normalized(rule)
            default: nil
            }
        }
    }

    private func normalized(_ rule: Rule) -> Rule {
        var rule = rule
        rule.process = .any
        rule.codeRequirement = nil
        rule.ports = .any
        rule.proto = .any
        rule.direction = .outgoing
        rule.userID = nil
        rule.profileID = nil
        rule.isPriority = false
        rule.expiration = .never
        rule.origin = .ruleGroup(id)
        return rule
    }
}
