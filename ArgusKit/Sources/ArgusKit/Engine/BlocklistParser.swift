import Foundation

/// The contents of a downloaded rule group or blocklist.
public struct ParsedRuleGroup: Sendable {
    public var name: String?
    public var summary: String?
    public var rules: [Rule] = []
    public var hosts: [String] = []
    public var domains: [String] = []
    public var addresses: [IPNetwork] = []

    public var compiled: CompiledBlocklist {
        CompiledBlocklist(domains: DomainSet(exact: hosts, suffixes: domains), addresses: IPRangeSet(networks: addresses))
    }
}

public enum BlocklistError: LocalizedError, Equatable {
    case empty
    case invalidJSON(String)
    case notText

    public var errorDescription: String? {
        switch self {
        case .empty: "The list contains no usable entries."
        case .invalidJSON(let detail): "The rule group isn't valid JSON: \(detail)"
        case .notText: "The download isn't a text file."
        }
    }
}

public enum BlocklistParser {
    public static func parse(_ data: Data, format: BlocklistFormat, groupID: UUID) throws -> ParsedRuleGroup {
        guard let text = String(data: data, encoding: .utf8) ?? String(data: data, encoding: .isoLatin1) else {
            throw BlocklistError.notText
        }
        let resolved = format == .automatic ? detectFormat(text) : format
        let result: ParsedRuleGroup = switch resolved {
        case .ruleGroupJSON: try parseRuleGroupJSON(data, groupID: groupID)
        case .hosts, .domains, .addresses, .automatic: parseLines(text, format: resolved)
        }
        guard !result.rules.isEmpty || !result.hosts.isEmpty || !result.domains.isEmpty || !result.addresses.isEmpty else {
            throw BlocklistError.empty
        }
        return result
    }

    public static func detectFormat(_ text: String) -> BlocklistFormat {
        let trimmed = text.drop { $0.isWhitespace }
        if trimmed.hasPrefix("{") { return .ruleGroupJSON }
        var hosts = 0, addresses = 0, domains = 0
        for line in trimmed.split(whereSeparator: \.isNewline).prefix(400) {
            let content = stripComment(line)
            guard !content.isEmpty else { continue }
            let fields = content.split(whereSeparator: \.isWhitespace)
            if fields.count >= 2, IPAddress(fields[0]) != nil { hosts += 1 } else if IPNetwork(fields[0]) != nil { addresses += 1 } else { domains += 1 }
        }
        if hosts >= max(addresses, domains), hosts > 0 { return .hosts }
        if addresses > domains { return .addresses }
        return .domains
    }

    static let ignoredHosts: Set<String> = [
        "localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback",
        "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0",
    ]

    static func stripComment(_ line: Substring) -> Substring {
        var content = line
        if let hash = content.firstIndex(of: "#") { content = content[..<hash] }
        let trimmed = content.trimmingCharacters(in: .whitespaces)
        if trimmed.hasPrefix("!") || trimmed.hasPrefix("//") || trimmed.hasPrefix("[") { return "" }
        return Substring(trimmed)
    }

    static func parseLines(_ text: String, format: BlocklistFormat) -> ParsedRuleGroup {
        var result = ParsedRuleGroup()
        var lines = text.split(whereSeparator: \.isNewline)[...]
        // Many lists announce themselves in a "# Title:" header.
        for line in lines.prefix(30) where line.hasPrefix("#") {
            let header = line.dropFirst().trimmingCharacters(in: .whitespaces)
            if let value = header.headerValue(for: ["Title:", "title:"]) { result.name = value }
            if let value = header.headerValue(for: ["Description:", "description:"]) { result.summary = value }
        }
        while let line = lines.popFirst() {
            let content = stripComment(line)
            guard !content.isEmpty else { continue }
            switch format {
            case .hosts:
                let fields = content.split(whereSeparator: \.isWhitespace)
                guard fields.count >= 2, IPAddress(fields[0]) != nil else { continue }
                for field in fields.dropFirst() {
                    if let host = DomainSet.normalize(field), !ignoredHosts.contains(host) { result.hosts.append(host) }
                }
            case .addresses:
                let field = content.split(whereSeparator: { $0.isWhitespace || $0 == ";" || $0 == "," }).first ?? content
                if let network = IPNetwork(field) { result.addresses.append(network) }
            default:
                if let domain = domainEntry(content) { result.domains.append(domain) }
            }
        }
        return result
    }

    /// Accepts plain domains, `*.domain`, adblock `||domain^` and dnsmasq `address=/domain/` entries.
    static func domainEntry(_ content: Substring) -> String? {
        var s = content
        if s.hasPrefix("@@") { return nil } // exception rules
        if s.hasPrefix("||") {
            s = s.dropFirst(2)
            guard let caret = s.firstIndex(where: { $0 == "^" || $0 == "$" || $0 == "/" }) else { return DomainSet.normalize(s) }
            if s[caret...].contains("$") { return nil } // modifiers narrow the rule beyond what DNS-level blocking can express
            s = s[..<caret]
        } else if s.hasPrefix("address=/") || s.hasPrefix("server=/") || s.hasPrefix("local=/") {
            let parts = s.split(separator: "/")
            guard parts.count >= 2 else { return nil }
            s = parts[1]
        } else if let space = s.firstIndex(where: \.isWhitespace) {
            s = s[..<space]
        }
        guard IPAddress(s) == nil else { return nil }
        return DomainSet.normalize(s)
    }

    // MARK: Little Snitch rule group JSON (.lsrules)

    static func parseRuleGroupJSON(_ data: Data, groupID: UUID) throws -> ParsedRuleGroup {
        let object: Any
        do { object = try JSONSerialization.jsonObject(with: data) } catch { throw BlocklistError.invalidJSON(error.localizedDescription) }
        guard let root = object as? [String: Any] else { throw BlocklistError.invalidJSON("top level is not an object") }
        var result = ParsedRuleGroup()
        result.name = root["name"] as? String
        result.summary = root["description"] as? String

        for (index, raw) in ((root["rules"] as? [[String: Any]]) ?? []).enumerated() {
            result.rules += rules(from: raw, index: index, groupID: groupID)
        }
        result.domains += strings(root["denied-remote-domains"]).compactMap(DomainSet.normalize)
        result.hosts += strings(root["denied-remote-hosts"]).compactMap(DomainSet.normalize)
        result.addresses += strings(root["denied-remote-addresses"]).compactMap(IPNetwork.init)
        return result
    }

    static func strings(_ value: Any?) -> [String] {
        if let array = value as? [String] { return array }
        if let string = value as? String {
            return string.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        }
        return []
    }

    static func rules(from raw: [String: Any], index: Int, groupID: UUID) -> [Rule] {
        let actionText = (raw["action"] as? String)?.lowercased()
        guard let action = actionText.flatMap(RuleAction.init(rawValue:)) else { return [] }
        let processText = raw["process"] as? String ?? "any"
        let process: ProcessMatch = processText == "any" ? .any : .path(processText)
        guard let ports = PortMatch.parse((raw["ports"] as? String) ?? (raw["ports"] as? Int).map(String.init) ?? "any") else { return [] }
        let proto: ProtocolMatch = switch (raw["protocol"] as? String)?.lowercased() {
        case "tcp", "6": .tcp
        case "udp", "17": .udp
        case "icmp", "icmpv6", "1", "58": .icmp
        default: .any
        }
        let direction: DirectionMatch = (raw["direction"] as? String) == "incoming" ? .incoming : .outgoing

        var remotes: [RemoteMatch] = []
        remotes += strings(raw["remote-hosts"]).compactMap(DomainSet.normalize).map(RemoteMatch.host)
        remotes += strings(raw["remote-domains"]).compactMap(DomainSet.normalize).map(RemoteMatch.domain)
        remotes += strings(raw["remote-addresses"]).filter { IPNetwork($0) != nil }.map(RemoteMatch.address)
        if remotes.isEmpty {
            switch (raw["remote"] as? String)?.lowercased() {
            case nil, "any": remotes = [.any]
            case "local-net", "multicast", "broadcast", "bonjour": remotes = [.localNetwork]
            default: return [] // dns-servers, bpf: not expressible yet
            }
        }

        return remotes.enumerated().map { offset, remote in
            Rule(
                id: UUID.stable("\(groupID)|\(index)|\(offset)|\(action)|\(processText)|\(remote)|\(ports)"),
                action: action, process: process, remote: remote, ports: ports, proto: proto, direction: direction,
                userID: (raw["owner"] as? String) == "me" ? getuid() : nil,
                isPriority: (raw["priority"] as? String) == "high",
                isEnabled: !((raw["disabled"] as? Bool) ?? false),
                notes: raw["notes"] as? String ?? "",
                origin: .ruleGroup(groupID)
            )
        }
    }

    /// Exports rules as a `.lsrules` rule group others can subscribe to.
    public static func exportRuleGroup(name: String, description: String, rules: [Rule]) throws -> Data {
        let exported: [[String: Any]] = rules.compactMap { rule in
            var entry: [String: Any] = ["action": rule.action.rawValue, "process": rule.process.path ?? "any"]
            switch rule.remote {
            case .any: entry["remote"] = "any"
            case .localNetwork: entry["remote"] = "local-net"
            case .host(let h): entry["remote-hosts"] = h
            case .domain(let d): entry["remote-domains"] = d
            case .address(let a): entry["remote-addresses"] = a
            }
            if rule.ports != .any { entry["ports"] = rule.ports.displayString.replacingOccurrences(of: " ", with: "") }
            if rule.proto != .any { entry["protocol"] = rule.proto.rawValue }
            if rule.direction == .incoming { entry["direction"] = "incoming" }
            if rule.isPriority { entry["priority"] = "high" }
            if !rule.isEnabled { entry["disabled"] = true }
            if !rule.notes.isEmpty { entry["notes"] = rule.notes }
            return entry
        }
        let root: [String: Any] = ["name": name, "description": description, "rules": exported]
        return try JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys])
    }
}

private extension String {
    func headerValue(for prefixes: [String]) -> String? {
        for prefix in prefixes where hasPrefix(prefix) {
            let value = dropFirst(prefix.count).trimmingCharacters(in: .whitespaces)
            return value.isEmpty ? nil : value
        }
        return nil
    }
}

extension UUID {
    /// A deterministic UUID, so rules from a refreshed rule group keep their identity.
    static func stable(_ text: String) -> UUID {
        let a = DomainSet.hash(text)
        let b = DomainSet.hash(String(text.reversed()))
        var bytes = [UInt8](repeating: 0, count: 16)
        for i in 0..<8 {
            bytes[i] = UInt8(truncatingIfNeeded: a >> (UInt64(i) * 8))
            bytes[8 + i] = UInt8(truncatingIfNeeded: b >> (UInt64(i) * 8))
        }
        bytes[6] = (bytes[6] & 0x0F) | 0x50 // version 5 layout
        bytes[8] = (bytes[8] & 0x3F) | 0x80
        return UUID(uuid: (bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                           bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]))
    }
}
