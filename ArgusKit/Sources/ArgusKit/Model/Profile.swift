import Foundation

/// What Argus does with a connection that no rule covers.
public enum FilterMode: String, Codable, Sendable, CaseIterable {
    /// Hold the connection and ask.
    case alert
    /// Allow it and remember it so a rule can be made later.
    case silentAllow
    /// Deny it and remember it so a rule can be made later.
    case silentDeny

    public var displayName: String {
        switch self {
        case .alert: "Ask Me"
        case .silentAllow: "Allow Silently"
        case .silentDeny: "Deny Silently"
        }
    }

    public var explanation: String {
        switch self {
        case .alert: "Argus asks before an app makes a connection it hasn't seen."
        case .silentAllow: "Unknown connections are allowed without asking. Review them later in the monitor."
        case .silentDeny: "Unknown connections are blocked without asking. Only explicitly allowed traffic gets through."
        }
    }

    public var symbolName: String {
        switch self {
        case .alert: "bell.badge"
        case .silentAllow: "checkmark.shield"
        case .silentDeny: "xmark.shield"
        }
    }
}

public enum InterfaceKind: String, Codable, Sendable {
    case wifi, ethernet, cellular, vpn, other

    public var symbolName: String {
        switch self {
        case .wifi: "wifi"
        case .ethernet: "cable.connector"
        case .cellular: "antenna.radiowaves.left.and.right"
        case .vpn: "lock.shield"
        case .other: "network"
        }
    }
}

/// A fingerprint of the network the Mac is attached to, used for automatic profile switching.
/// The router's hardware address is the most stable signal; the Wi-Fi name is used when known.
public struct NetworkIdentity: Codable, Hashable, Sendable {
    public var interface: InterfaceKind
    public var ssid: String?
    public var gatewayAddress: String?
    public var gatewayHardwareAddress: String?

    public init(interface: InterfaceKind, ssid: String? = nil, gatewayAddress: String? = nil, gatewayHardwareAddress: String? = nil) {
        self.interface = interface
        self.ssid = ssid
        self.gatewayAddress = gatewayAddress
        self.gatewayHardwareAddress = gatewayHardwareAddress
    }

    public var displayName: String {
        if let ssid, !ssid.isEmpty { return ssid }
        let kind = switch interface {
        case .wifi: "Wi-Fi network"
        case .ethernet: "Wired network"
        case .cellular: "Cellular network"
        case .vpn: "VPN"
        case .other: "Network"
        }
        return gatewayAddress.map { "\(kind) at \($0)" } ?? kind
    }

    /// Whether `other` is the same physical network.
    public func matches(_ other: NetworkIdentity) -> Bool {
        if let mac = gatewayHardwareAddress, let otherMAC = other.gatewayHardwareAddress { return mac.lowercased() == otherMAC.lowercased() }
        if let ssid, let otherSSID = other.ssid { return ssid == otherSSID }
        if let gateway = gatewayAddress, let otherGateway = other.gatewayAddress { return gateway == otherGateway && interface == other.interface }
        return false
    }
}

/// A named set of rules plus behaviour that can be switched manually or by network.
public struct Profile: Codable, Hashable, Sendable, Identifiable {
    public var id: UUID
    public var name: String
    public var symbolName: String
    /// Overrides the global mode while this profile is active.
    public var modeOverride: FilterMode?
    /// Networks that activate this profile automatically.
    public var networks: [NetworkIdentity]
    public var notes: String

    public init(id: UUID = UUID(), name: String, symbolName: String = "person.crop.circle", modeOverride: FilterMode? = nil, networks: [NetworkIdentity] = [], notes: String = "") {
        self.id = id
        self.name = name
        self.symbolName = symbolName
        self.modeOverride = modeOverride
        self.networks = networks
        self.notes = notes
    }

    public static let suggestedSymbols = ["house", "building.2", "cup.and.saucer", "airplane", "lock.shield", "person.crop.circle", "briefcase", "tram", "moon.stars", "gamecontroller"]
}
