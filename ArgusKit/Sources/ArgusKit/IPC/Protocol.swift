import Foundation

public enum ArgusVersion {
    public static let marketing = "1.0"
    public static let protocolVersion = 1
}

/// Where the firewall engine is running.
public enum EngineHost: String, Codable, Sendable {
    /// Inside the system extension: connections can be held, allowed and blocked.
    case networkExtension
    /// Inside the app, fed by the system's network statistics: observe only.
    case monitor

    public var canEnforce: Bool { self == .networkExtension }
}

public enum ClientRole: String, Codable, Sendable {
    case app, commandLine
}

public struct ClientHello: Codable, Sendable {
    public var role: ClientRole
    /// Interactive clients receive connection alerts.
    public var wantsAlerts: Bool
    public var protocolVersion: Int

    public init(role: ClientRole, wantsAlerts: Bool) {
        self.role = role
        self.wantsAlerts = wantsAlerts
        protocolVersion = ArgusVersion.protocolVersion
    }
}

public struct ServerHello: Codable, Sendable {
    public var host: EngineHost
    public var version: String
    public var protocolVersion: Int
    /// The user the server believes the client runs as.
    public var clientUserID: UInt32
    public var canCapture: Bool
}

public struct NetworkReport: Codable, Sendable, Hashable {
    /// Profile associated with the network, if any.
    public var profileID: UUID?
    /// False the first time Argus sees this network, so the app can ask which profile to use.
    public var isKnown: Bool
    public var switched: Bool
}

public enum ArgusRequest: Codable, Sendable {
    case hello(ClientHello)
    case getState
    case getActivity(since: UInt64)
    case getTraffic(TrafficQuery)

    case updateSettings(FirewallSettings)
    case setMode(FilterMode)
    case setProtection(Bool)
    /// Allows everything until the date; nil resumes protection now.
    case pauseProtection(until: Date?)

    case saveRule(Rule)
    case deleteRules([UUID])
    case setRulesEnabled([UUID], Bool)

    case saveProfile(Profile)
    case deleteProfile(UUID)
    case activateProfile(UUID?)
    case reportNetwork(NetworkIdentity)
    /// Remembers a network and binds it to a profile (nil = just remember, no profile).
    case assignNetwork(NetworkIdentity, profileID: UUID?)

    case saveRuleGroup(RuleGroup)
    case deleteRuleGroup(UUID)
    case refreshRuleGroups([UUID]?)
    /// Adds a rule group from a local file's contents.
    case importRuleGroup(name: String, contents: Data, format: BlocklistFormat)

    case pendingAlerts
    /// The alert is on screen now, so its countdown starts.
    case alertShown(UUID)
    case resolveAlert(UUID, AlertDecision)

    case startCapture(CaptureRequest)
    case stopCapture(UUID)
    case listCaptures
    case fetchCapture(UUID)
    case deleteCapture(UUID)

    case exportBackup
    case importBackup(Data, merge: Bool)
    case clearActivity

    /// Requests that change configuration and therefore honour the settings lock.
    public var isMutating: Bool {
        switch self {
        case .hello, .getState, .getActivity, .getTraffic, .pendingAlerts, .alertShown, .listCaptures, .fetchCapture, .exportBackup, .reportNetwork:
            false
        default:
            true
        }
    }
}

public enum ArgusError: Error, Codable, Sendable, Equatable, LocalizedError {
    case locked
    case notFound(String)
    case invalid(String)
    case unsupported(String)
    case failed(String)
    case disconnected

    public var errorDescription: String? {
        switch self {
        case .locked: "Settings are locked. An administrator must unlock them first."
        case .notFound(let what): "\(what) was not found."
        case .invalid(let why): why
        case .unsupported(let why): why
        case .failed(let why): why
        case .disconnected: "Lost connection to the Argus engine."
        }
    }
}

public enum ArgusResponse: Codable, Sendable {
    case ok
    case error(ArgusError)
    case hello(ServerHello)
    case state(FirewallState)
    case activity(ActivitySnapshot)
    case traffic([TrafficBucket])
    case alerts([ConnectionAlert])
    case network(NetworkReport)
    case capture(CaptureSession)
    case captures([CaptureSession])
    case data(Data)
}

/// Pushed from the engine to connected clients.
public enum ArgusEvent: Codable, Sendable {
    case alert(ConnectionAlert)
    case alertResolved(UUID)
    case stateChanged(revision: UInt64)
    /// Something the user should probably hear about (BPF access, signature mismatch...).
    case notice(ActivityEvent)
}

/// One frame on the wire.
public enum WireMessage: Codable, Sendable {
    case request(id: UInt64, ArgusRequest, authorization: Data?)
    case response(id: UInt64, ArgusResponse)
    case event(ArgusEvent)

    public func encoded() throws -> Data { try WireMessage.encoder.encode(self) }

    public static func decode(_ data: Data) throws -> WireMessage { try decoder.decode(WireMessage.self, from: data) }

    static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        return encoder
    }()

    static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        return decoder
    }()
}
