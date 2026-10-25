import Foundation

public extension VerdictReason {
    /// Why a connection was allowed or denied, in words.
    func explanation(in state: FirewallState) -> String {
        switch self {
        case .rule(let id):
            if let rule = state.rules.first(where: { $0.id == id }) { return "Rule: \(rule.summary)" }
            if let group = state.ruleGroups.first(where: { $0.rules.contains { $0.id == id } }) { return "Rule from “\(group.name)”" }
            return "A rule that has since been removed"
        case .blocklist(let id):
            return "Blocklist: \(state.ruleGroup(id: id)?.name ?? "removed list")"
        case .mode(let mode):
            return mode == .silentAllow ? "Allowed silently (no rule yet)" : "Denied silently (no rule yet)"
        case .alertAnswer: return "Answered in an alert, once"
        case .alertTimeout: return "Alert wasn't answered in time"
        case .unattended: return "Nobody was around to ask"
        case .appleSoftware: return "Software signed by Apple"
        case .signedSoftware: return "Software from an identified developer"
        case .localNetwork: return "Local network traffic"
        case .protectionOff: return "Protection was off"
        case .paused: return "Protection was paused"
        case .signatureMismatch: return "Code signature no longer matches the rule"
        case .observed: return "Observed only (monitor mode)"
        }
    }

    var ruleID: UUID? {
        switch self {
        case .rule(let id), .signatureMismatch(let id): id
        default: nil
        }
    }
}

public enum Formatting {
    /// "0 B", "512 B", "4.2 MB" — compact enough for menus and table cells.
    public static func bytes(_ count: UInt64) -> String {
        count < 1024 ? "\(count) B" : ByteCountFormatter.string(fromByteCount: Int64(clamping: count), countStyle: .binary)
    }

    public static func rate(_ bytesPerSecond: Double) -> String {
        guard bytesPerSecond >= 1024 else { return "\(Int(max(0, bytesPerSecond))) B/s" }
        return ByteCountFormatter.string(fromByteCount: Int64(bytesPerSecond), countStyle: .binary) + "/s"
    }

    /// Well-known service names for common ports.
    public static func service(port: UInt16, proto: TransportProtocol) -> String? {
        switch (port, proto) {
        case (443, .udp): "QUIC"
        case (53, _): "DNS"
        case (80, _): "HTTP"
        case (443, _): "HTTPS"
        case (22, _): "SSH"
        case (25, _), (465, _), (587, _): "SMTP"
        case (993, _): "IMAPS"
        case (995, _): "POP3S"
        case (123, _): "NTP"
        case (5223, _): "Apple Push"
        case (5353, _): "Bonjour"
        case (853, _): "DNS over TLS"
        case (3478, _), (3479, _): "STUN"
        case (1900, _): "SSDP"
        case (67, _), (68, _): "DHCP"
        case (8080, _): "HTTP alt"
        default: nil
        }
    }

    public static func endpoint(port: UInt16, proto: TransportProtocol) -> String {
        let service = service(port: port, proto: proto).map { " (\($0))" } ?? ""
        return "\(proto) \(port)\(service)"
    }
}
