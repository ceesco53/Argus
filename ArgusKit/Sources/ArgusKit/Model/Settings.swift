import Foundation

public struct FirewallSettings: Codable, Hashable, Sendable {
    /// Master switch. When off every connection is allowed and nothing is filtered.
    public var protectionEnabled = true
    /// While set and in the future, everything is allowed; protection resumes by itself.
    public var pausedUntil: Date?
    public var mode: FilterMode = .alert
    public var activeProfileID: UUID?
    public var autoSwitchProfiles = true

    /// Allow unknown connections from software signed by Apple without asking.
    public var allowAppleSoftware = true
    /// Allow unknown connections from App Store and Developer ID software without asking.
    public var allowSignedSoftware = false
    /// Allow unknown connections to the local network (printers, NAS, AirPlay) without asking.
    public var allowLocalNetwork = true

    /// Seconds an alert waits for an answer before applying `alertTimeoutAction` once.
    public var alertTimeout: TimeInterval = 90
    public var alertTimeoutAction: RuleAction = .deny
    /// What to do with unknown connections when no Argus app is running to ask.
    public var unattendedAction: RuleAction = .allow

    /// Deny connections whose program no longer satisfies the code requirement a rule was made for.
    public var enforceCodeSignatures = true
    /// Watch for programs reading raw network traffic through /dev/bpf.
    public var monitorPacketCapture = true
    /// Learn hostnames from DNS answers so rules work for apps that connect by address.
    public var learnHostnamesFromDNS = true

    /// Suggest an answer in alerts from reference lists, the app's identity and past decisions.
    public var suggestAnswers = true
    /// When an alert goes unanswered, follow a confident suggestion instead of `alertTimeoutAction`.
    public var alertTimeoutFollowsAdvice = false

    /// Require administrator authentication to change rules and settings.
    public var lockEnabled = false
    /// While locked, still let alerts create rules.
    public var alertsAllowedWhenLocked = true

    public init() {}

    public func isPaused(at now: Date = Date()) -> Bool { pausedUntil.map { $0 > now } ?? false }

    public init(from decoder: Decoder) throws {
        // Decode leniently so settings files from older versions keep working.
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = FirewallSettings()
        protectionEnabled = try c.decodeIfPresent(Bool.self, forKey: .protectionEnabled) ?? d.protectionEnabled
        pausedUntil = try c.decodeIfPresent(Date.self, forKey: .pausedUntil)
        mode = try c.decodeIfPresent(FilterMode.self, forKey: .mode) ?? d.mode
        activeProfileID = try c.decodeIfPresent(UUID.self, forKey: .activeProfileID)
        autoSwitchProfiles = try c.decodeIfPresent(Bool.self, forKey: .autoSwitchProfiles) ?? d.autoSwitchProfiles
        allowAppleSoftware = try c.decodeIfPresent(Bool.self, forKey: .allowAppleSoftware) ?? d.allowAppleSoftware
        allowSignedSoftware = try c.decodeIfPresent(Bool.self, forKey: .allowSignedSoftware) ?? d.allowSignedSoftware
        allowLocalNetwork = try c.decodeIfPresent(Bool.self, forKey: .allowLocalNetwork) ?? d.allowLocalNetwork
        alertTimeout = try c.decodeIfPresent(TimeInterval.self, forKey: .alertTimeout) ?? d.alertTimeout
        alertTimeoutAction = try c.decodeIfPresent(RuleAction.self, forKey: .alertTimeoutAction) ?? d.alertTimeoutAction
        unattendedAction = try c.decodeIfPresent(RuleAction.self, forKey: .unattendedAction) ?? d.unattendedAction
        enforceCodeSignatures = try c.decodeIfPresent(Bool.self, forKey: .enforceCodeSignatures) ?? d.enforceCodeSignatures
        monitorPacketCapture = try c.decodeIfPresent(Bool.self, forKey: .monitorPacketCapture) ?? d.monitorPacketCapture
        learnHostnamesFromDNS = try c.decodeIfPresent(Bool.self, forKey: .learnHostnamesFromDNS) ?? d.learnHostnamesFromDNS
        suggestAnswers = try c.decodeIfPresent(Bool.self, forKey: .suggestAnswers) ?? d.suggestAnswers
        alertTimeoutFollowsAdvice = try c.decodeIfPresent(Bool.self, forKey: .alertTimeoutFollowsAdvice) ?? d.alertTimeoutFollowsAdvice
        lockEnabled = try c.decodeIfPresent(Bool.self, forKey: .lockEnabled) ?? d.lockEnabled
        alertsAllowedWhenLocked = try c.decodeIfPresent(Bool.self, forKey: .alertsAllowedWhenLocked) ?? d.alertsAllowedWhenLocked
    }
}

/// The persistent configuration: everything a backup contains.
public struct FirewallState: Codable, Hashable, Sendable {
    public var settings = FirewallSettings()
    public var rules: [Rule] = []
    public var profiles: [Profile] = []
    public var ruleGroups: [RuleGroup] = []
    /// Networks the user has already been asked about, so they aren't asked twice.
    public var knownNetworks: [NetworkIdentity] = []
    public var revision: UInt64 = 0

    public init() {}

    public var activeProfile: Profile? {
        guard let id = settings.activeProfileID else { return nil }
        return profiles.first { $0.id == id }
    }

    public var effectiveMode: FilterMode { activeProfile?.modeOverride ?? settings.mode }

    public func profile(id: UUID?) -> Profile? {
        guard let id else { return nil }
        return profiles.first { $0.id == id }
    }

    public func ruleGroup(id: UUID) -> RuleGroup? { ruleGroups.first { $0.id == id } }

    /// Rules for a newly installed Argus: keep the Mac's own plumbing working.
    public static func initial() -> FirewallState {
        var state = FirewallState()
        state.rules = [
            Rule(action: .allow, process: .path("/usr/sbin/mDNSResponder"), remote: .any, proto: .any, direction: .both,
                 notes: "Resolves hostnames for every app. Blocking it breaks almost everything.", origin: .defaults),
            Rule(action: .allow, process: .any, remote: .any, ports: .ranges([PortRange(67, 68)]), proto: .udp, direction: .both,
                 notes: "DHCP: lets the Mac obtain an address on a network.", origin: .defaults),
            Rule(action: .allow, process: .path("/usr/libexec/timed"), remote: .any, ports: .single(123), proto: .udp,
                 notes: "Keeps the clock in sync.", origin: .defaults),
        ]
        state.profiles = [
            Profile(name: "Home", symbolName: "house"),
            Profile(name: "Public Wi-Fi", symbolName: "cup.and.saucer", modeOverride: .alert,
                    notes: "Use on untrusted networks. Local-network rules don't carry over."),
        ]
        return state
    }
}
