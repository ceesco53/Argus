import Foundation

public enum BlocklistFormat: String, Codable, Sendable, CaseIterable {
    /// Detect from content.
    case automatic
    /// Little Snitch `.lsrules` JSON.
    case ruleGroupJSON
    /// `/etc/hosts` style; each entry blocks that exact host.
    case hosts
    /// One domain per line; each entry blocks the domain and its subdomains.
    case domains
    /// One address or CIDR network per line.
    case addresses

    public var displayName: String {
        switch self {
        case .automatic: "Detect automatically"
        case .ruleGroupJSON: "Rule group (.lsrules)"
        case .hosts: "Hosts file"
        case .domains: "Domain list"
        case .addresses: "IP address list"
        }
    }
}

/// A set of rules or blocklist entries maintained outside Argus, usually a subscription URL.
public struct RuleGroup: Codable, Hashable, Sendable, Identifiable {
    public var id: UUID
    public var name: String
    public var summary: String
    public var url: URL?
    /// Identifies the built-in catalogue entry this group was created from.
    public var catalogID: String?
    public var isEnabled: Bool
    public var format: BlocklistFormat
    public var updateInterval: TimeInterval
    public var lastUpdated: Date?
    public var lastAttempt: Date?
    public var lastError: String?
    public var hostCount: Int
    public var domainCount: Int
    public var addressCount: Int
    /// Ordinary rules shipped by a `.lsrules` group.
    public var rules: [Rule]

    public init(
        id: UUID = UUID(),
        name: String,
        summary: String = "",
        url: URL? = nil,
        catalogID: String? = nil,
        isEnabled: Bool = true,
        format: BlocklistFormat = .automatic,
        updateInterval: TimeInterval = 86_400
    ) {
        self.id = id
        self.name = name
        self.summary = summary
        self.url = url
        self.catalogID = catalogID
        self.isEnabled = isEnabled
        self.format = format
        self.updateInterval = updateInterval
        hostCount = 0
        domainCount = 0
        addressCount = 0
        rules = []
    }

    public var entryCount: Int { hostCount + domainCount + addressCount + rules.count }

    public func isDue(now: Date = Date()) -> Bool {
        guard url != nil, isEnabled else { return false }
        guard let lastAttempt else { return true }
        let interval = lastError == nil ? updateInterval : min(updateInterval, 3600)
        return now.timeIntervalSince(lastAttempt) >= interval
    }
}

/// Community-maintained lists offered in the Blocklists view.
public struct CatalogEntry: Identifiable, Sendable, Hashable {
    public enum Category: String, Sendable, CaseIterable {
        case essentials = "Essentials"
        case privacy = "Privacy & Tracking"
        case security = "Security"
        case special = "Special Purpose"
    }

    public let id: String
    public let name: String
    public let maintainer: String
    public let summary: String
    public let url: URL
    public let homepage: URL
    public let format: BlocklistFormat
    public let category: Category
    public let approximateEntries: Int
    public let isRecommended: Bool

    /// "HaGeZi Multi Light", but not "FireHOL FireHOL Level 1".
    public var displayName: String { name.hasPrefix(maintainer) ? name : "\(maintainer) \(name)" }
}

public enum BlocklistCatalog {
    public static let entries: [CatalogEntry] = [
        CatalogEntry(
            id: "hagezi-light", name: "Multi Light", maintainer: "HaGeZi",
            summary: "Blocks ads, trackers and telemetry with almost no risk of breaking websites. A great default.",
            url: URL(string: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt")!,
            homepage: URL(string: "https://github.com/hagezi/dns-blocklists")!,
            format: .domains, category: .essentials, approximateEntries: 70_000, isRecommended: true),
        CatalogEntry(
            id: "hagezi-multi", name: "Multi Normal", maintainer: "HaGeZi",
            summary: "Broader ad, tracker, metrics and badware coverage. Rarely breaks anything.",
            url: URL(string: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/multi-onlydomains.txt")!,
            homepage: URL(string: "https://github.com/hagezi/dns-blocklists")!,
            format: .domains, category: .essentials, approximateEntries: 160_000, isRecommended: false),
        CatalogEntry(
            id: "hagezi-pro", name: "Multi Pro", maintainer: "HaGeZi",
            summary: "Aggressive privacy protection for people who don't mind occasionally allowing something by hand.",
            url: URL(string: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt")!,
            homepage: URL(string: "https://github.com/hagezi/dns-blocklists")!,
            format: .domains, category: .privacy, approximateEntries: 190_000, isRecommended: false),
        CatalogEntry(
            id: "stevenblack", name: "Unified Hosts", maintainer: "Steven Black",
            summary: "The classic consolidated hosts file of adware and malware hosts.",
            url: URL(string: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts")!,
            homepage: URL(string: "https://github.com/StevenBlack/hosts")!,
            format: .hosts, category: .privacy, approximateEntries: 80_000, isRecommended: false),
        CatalogEntry(
            id: "pgl", name: "Ad Servers", maintainer: "Peter Lowe",
            summary: "A small, long-running, hand-curated list of ad and tracking servers.",
            url: URL(string: "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext")!,
            homepage: URL(string: "https://pgl.yoyo.org/adservers/")!,
            format: .hosts, category: .privacy, approximateEntries: 3_500, isRecommended: false),
        CatalogEntry(
            id: "oisd-small", name: "OISD Small", maintainer: "oisd.nl",
            summary: "Blocks ads, phishing, malvertising, malware, spyware, ransomware and scams with a tiny false-positive rate.",
            url: URL(string: "https://small.oisd.nl/domainswild2")!,
            homepage: URL(string: "https://oisd.nl")!,
            format: .domains, category: .essentials, approximateEntries: 60_000, isRecommended: false),
        CatalogEntry(
            id: "hagezi-tif", name: "Threat Intelligence Feeds", maintainer: "HaGeZi",
            summary: "Malware, phishing, scam, cryptojacking and command-and-control domains. Large (~1M entries).",
            url: URL(string: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif-onlydomains.txt")!,
            homepage: URL(string: "https://github.com/hagezi/dns-blocklists")!,
            format: .domains, category: .security, approximateEntries: 1_000_000, isRecommended: false),
        CatalogEntry(
            id: "firehol-level1", name: "FireHOL Level 1", maintainer: "FireHOL",
            summary: "Internet addresses used by attackers and known-bad infrastructure. Your local network is never affected.",
            url: URL(string: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset")!,
            homepage: URL(string: "https://iplists.firehol.org")!,
            format: .addresses, category: .security, approximateEntries: 4_500, isRecommended: true),
        CatalogEntry(
            id: "hagezi-apple", name: "Apple Native Tracker", maintainer: "HaGeZi",
            summary: "Blocks the telemetry and analytics endpoints built into macOS and Apple apps.",
            url: URL(string: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/native.apple-onlydomains.txt")!,
            homepage: URL(string: "https://github.com/hagezi/dns-blocklists")!,
            format: .domains, category: .special, approximateEntries: 100, isRecommended: false),
        CatalogEntry(
            id: "hagezi-doh", name: "Encrypted DNS Bypass", maintainer: "HaGeZi",
            summary: "Blocks DNS-over-HTTPS servers so apps can't route around your blocklists.",
            url: URL(string: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/doh-onlydomains.txt")!,
            homepage: URL(string: "https://github.com/hagezi/dns-blocklists")!,
            format: .domains, category: .special, approximateEntries: 3_000, isRecommended: false),
    ]

    /// Lists Argus downloads only to advise in alerts; they never block anything themselves.
    /// (A host on a list you've enabled is blocked before anyone is asked, so only lists you
    /// haven't enabled can say anything about an alert.)
    public static let references: [ReferenceList] = [
        ReferenceList(
            id: "ref-hagezi-tif-medium", kind: .threat, name: "HaGeZi Threat Intelligence",
            url: URL(string: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium-onlydomains.txt")!),
        ReferenceList(
            id: "ref-hagezi-pro", kind: .tracker, name: "HaGeZi Multi Pro",
            url: URL(string: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt")!),
    ]

    public static func entry(id: String?) -> CatalogEntry? {
        guard let id else { return nil }
        return entries.first { $0.id == id }
    }
}

public struct ReferenceList: Identifiable, Sendable, Hashable {
    public enum Kind: String, Sendable { case threat, tracker }

    public let id: String
    public let kind: Kind
    public let name: String
    public let url: URL
}
