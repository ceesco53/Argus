import ArgusKit
import Foundation
import Observation
import Security

/// Keeps rules, profiles and blocklist subscriptions the same on every Mac signed in to the
/// same iCloud account, through iCloud key-value storage. Temporary rules, rules that come from
/// rule groups, and settings stay on each Mac.
@MainActor @Observable
final class CloudSync {
    enum Availability: Equatable {
        case available
        /// This build isn't signed with the iCloud key-value storage entitlement.
        case notEntitled
        case signedOut
    }

    /// A sync that would have removed a lot at once, waiting for the user's decision.
    enum Conflict: Equatable {
        /// Syncing this Mac would remove this many rules, profiles and blocklists from the other Macs.
        case wouldRemoveElsewhere(Int)
        /// iCloud would remove this many from this Mac.
        case wouldRemoveHere(Int)
    }

    private(set) var lastSynced: Date?
    private(set) var problem: String?
    private(set) var conflict: Conflict?

    @ObservationIgnored private weak var model: AppModel?
    @ObservationIgnored private var observer: NSObjectProtocol?
    @ObservationIgnored private var pendingUpload: Task<Void, Never>?
    @ObservationIgnored private var applyingRemote = false

    static let key = "argus.configuration.v1"
    private static let enabledKey = "iCloudSync"
    private static let syncedIDsKey = "iCloudSyncedIDs"
    /// Which engine's configuration `syncedIDs` came from.
    private static let syncedEngineKey = "iCloudSyncedEngine"

    /// Never in demo mode: its made-up rules must not reach the real ones on other Macs.
    var isEnabled: Bool { !DebugLaunch.demo && UserDefaults.standard.bool(forKey: CloudSync.enabledKey) }

    var availability: Availability {
        guard let task = SecTaskCreateFromSelf(nil),
              SecTaskCopyValueForEntitlement(task, "com.apple.developer.ubiquity-kvstore-identifier" as CFString, nil) != nil
        else { return .notEntitled }
        return FileManager.default.ubiquityIdentityToken == nil ? .signedOut : .available
    }

    private var deviceID: String {
        if let id = UserDefaults.standard.string(forKey: "iCloudSyncDevice") { return id }
        let id = UUID().uuidString
        UserDefaults.standard.set(id, forKey: "iCloudSyncDevice")
        return id
    }

    // MARK: Payload

    struct SyncedGroup: Codable, Equatable {
        var id: UUID
        var name: String
        var summary: String
        var url: URL
        var catalogID: String?
        var isEnabled: Bool
        var format: BlocklistFormat
        /// Always set by this version (nil only from older ones, which don't know about scopes),
        /// so an older Mac's upload never turns a browsers-only list into one for every app.
        var appliesTo: AppScope?
    }

    /// Ad Domains, the user's own list, which nothing downloads: it travels whole, newest wins.
    struct SyncedAdDomains: Codable, Equatable {
        var isEnabled: Bool
        var appliesTo: AppScope?
        var rules: [Rule]
        var modifiedAt: Date
    }

    struct Payload: Codable {
        var device: String
        var updated: Date
        var rules: [Rule]
        var profiles: [Profile]
        var groups: [SyncedGroup]
        /// Older versions don't send it (and ignore it).
        var adDomains: SyncedAdDomains?
        /// Deletions, so another Mac removes them too instead of syncing them back.
        var deleted: [UUID: Date]

        /// Same content, ignoring timestamps a save adds (prevents two Macs re-uploading forever).
        func sameContent(as other: Payload) -> Bool {
            func normalized(_ rules: [Rule]) -> [Rule] {
                rules.map { var rule = $0; rule.modifiedAt = .distantPast; return rule }.sorted { $0.id.uuidString < $1.id.uuidString }
            }
            return normalized(rules) == normalized(other.rules)
                && profiles.sorted { $0.id.uuidString < $1.id.uuidString } == other.profiles.sorted { $0.id.uuidString < $1.id.uuidString }
                && groups.sorted { $0.id.uuidString < $1.id.uuidString } == other.groups.sorted { $0.id.uuidString < $1.id.uuidString }
                && adDomains.map { ($0.isEnabled, $0.appliesTo, normalized($0.rules)) } ?? (false, nil, [])
                    == other.adDomains.map { ($0.isEnabled, $0.appliesTo, normalized($0.rules)) } ?? (false, nil, [])
                && Set(deleted.keys) == Set(other.deleted.keys)
        }
    }

    static func syncable(_ rule: Rule) -> Bool { rule.expiration == .never && !rule.isFromRuleGroup }

    // MARK: Lifecycle

    func start(model: AppModel) {
        self.model = model
        observer = NotificationCenter.default.addObserver(
            forName: NSUbiquitousKeyValueStore.didChangeExternallyNotification, object: NSUbiquitousKeyValueStore.default, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in await self?.pull() }
        }
        guard isEnabled, availability == .available else { return }
        NSUbiquitousKeyValueStore.default.synchronize()
        Task { await pull() }
    }

    func setEnabled(_ enabled: Bool) {
        UserDefaults.standard.set(enabled, forKey: CloudSync.enabledKey)
        problem = nil
        conflict = nil
        guard enabled, availability == .available else { return }
        NSUbiquitousKeyValueStore.default.synchronize()
        Task {
            await pull()
            upload()
        }
    }

    /// The configuration changed on this Mac.
    func localChanged() {
        guard isEnabled, !applyingRemote, availability == .available, model?.engineHoldsConfiguration == true else { return }
        pendingUpload?.cancel()
        pendingUpload = Task {
            try? await Task.sleep(for: .seconds(4))
            guard !Task.isCancelled else { return }
            upload()
        }
    }

    // MARK: Upload

    private var syncedIDs: Set<UUID> {
        get { Set((UserDefaults.standard.stringArray(forKey: CloudSync.syncedIDsKey) ?? []).compactMap(UUID.init(uuidString:))) }
        set { UserDefaults.standard.set(newValue.map(\.uuidString), forKey: CloudSync.syncedIDsKey) }
    }

    private func readRemote() -> Payload? {
        guard let data = NSUbiquitousKeyValueStore.default.data(forKey: CloudSync.key) else { return nil }
        return try? JSONDecoder().decode(Payload.self, from: data)
    }

    private func localIDs(_ state: FirewallState) -> Set<UUID> {
        Set(state.rules.filter(CloudSync.syncable).map(\.id) + state.profiles.map(\.id)
            + state.ruleGroups.filter { $0.url != nil || $0.isAdDomains }.map(\.id))
    }

    /// The engine whose configuration is being synced, so a different engine's items aren't taken
    /// for deletions.
    private var engineKind: String { model?.engine == .filter ? "filter" : "monitor" }
    private var baselineIsThisEngine: Bool { UserDefaults.standard.string(forKey: CloudSync.syncedEngineKey) == engineKind }

    private func setBaseline(_ ids: Set<UUID>) {
        syncedIDs = ids
        UserDefaults.standard.set(engineKind, forKey: CloudSync.syncedEngineKey)
    }

    /// - Parameter force: the user agreed to a large removal.
    private func upload(force: Bool = false) {
        guard let model, model.engineHoldsConfiguration, conflict == nil || force else { return }
        let state = model.state
        let remote = readRemote()
        let now = Date()
        let present = localIDs(state)
        // Deleted here since the last sync. Items another engine had aren't deletions: this engine
        // simply never had them.
        let removed = baselineIsThisEngine ? syncedIDs.subtracting(present) : []
        if !force, SyncSafety.needsConfirmation(removing: removed.count, of: syncedIDs.count) {
            pause(.wouldRemoveElsewhere(removed.count))
            return
        }
        var deleted = remote?.deleted ?? [:]
        for id in removed where deleted[id] == nil { deleted[id] = now }
        for id in present { deleted[id] = nil }
        deleted = deleted.filter { now.timeIntervalSince($0.value) < 60 * 86_400 }
        let payload = Payload(
            device: deviceID, updated: now,
            rules: state.rules.filter(CloudSync.syncable),
            profiles: state.profiles,
            groups: state.ruleGroups.compactMap { group in
                group.url.map { SyncedGroup(id: group.id, name: group.name, summary: group.summary, url: $0, catalogID: group.catalogID,
                                            isEnabled: group.isEnabled, format: group.format, appliesTo: group.appliesTo ?? .allApps) }
            },
            adDomains: state.adDomains.map { group in
                SyncedAdDomains(isEnabled: group.isEnabled, appliesTo: group.appliesTo ?? .allApps, rules: group.rules,
                                modifiedAt: group.modifiedAt ?? .distantPast)
            },
            deleted: deleted)
        setBaseline(present)
        if let remote, payload.sameContent(as: remote) { return }
        guard let data = try? JSONEncoder().encode(payload), data.count < 900_000 else {
            problem = "There are too many rules to sync through iCloud (the limit is about 1 MB)."
            return
        }
        NSUbiquitousKeyValueStore.default.set(data, forKey: CloudSync.key)
        NSUbiquitousKeyValueStore.default.synchronize()
        lastSynced = now
        problem = nil
    }

    // MARK: Download

    /// Merges what other Macs uploaded: newer versions win; deletions apply to older copies.
    /// - Parameters:
    ///   - force: the user agreed to a large removal.
    ///   - restoring: bring back what this Mac removed, from iCloud.
    func pull(force: Bool = false, restoring: Bool = false) async {
        guard isEnabled, availability == .available, let model, model.engineHoldsConfiguration,
              conflict == nil || force, let remote = readRemote() else { return }
        let state = model.state
        // Don't resurrect what this Mac just deleted (unless asked to).
        let deletedHere = baselineIsThisEngine && !restoring ? syncedIDs.subtracting(localIDs(state)) : []
        func same(_ a: Rule, _ b: Rule) -> Bool {
            var a = a, b = b
            a.modifiedAt = .distantPast
            b.modifiedAt = .distantPast
            return a == b
        }

        var rulesToSave: [Rule] = []
        var newRules: [Rule] = []
        for rule in remote.rules where !deletedHere.contains(rule.id) {
            if let mine = state.rules.first(where: { $0.id == rule.id }) {
                if !same(mine, rule), rule.modifiedAt > mine.modifiedAt { rulesToSave.append(rule) }
            } else {
                newRules.append(rule)
            }
        }
        // A rule that does exactly what one here does (each Mac's starter rules, say) isn't new.
        rulesToSave += RuleAnalysis.withoutDuplicates(newRules, of: state.rules)
        let rulesToDelete = state.rules.filter { rule in remote.deleted[rule.id].map { rule.modifiedAt < $0 } ?? false }.map(\.id)
        let profilesToSave = remote.profiles.filter { profile in
            !deletedHere.contains(profile.id) && state.profile(id: profile.id) != profile && remote.device != deviceID
        }
        let profilesToDelete = state.profiles.filter { remote.deleted[$0.id] != nil }.map(\.id)
        var groupsToSave: [RuleGroup] = remote.groups.compactMap { synced in
            guard !deletedHere.contains(synced.id) else { return nil }
            if var mine = state.ruleGroup(id: synced.id) {
                // Switching "Ads in Browsers" to another level changes the list's address.
                let scopeChanged = synced.appliesTo.map { $0 != (mine.appliesTo ?? .allApps) } ?? false
                guard mine.isEnabled != synced.isEnabled || mine.name != synced.name || mine.url != synced.url || scopeChanged,
                      remote.device != deviceID else { return nil }
                mine.isEnabled = synced.isEnabled
                mine.name = synced.name
                if mine.url != synced.url {
                    mine.url = synced.url
                    mine.catalogID = synced.catalogID
                    mine.summary = synced.summary
                    mine.format = synced.format
                }
                if let scope = synced.appliesTo { mine.appliesTo = scope }
                return mine
            }
            let scope = synced.appliesTo ?? .allApps
            guard !state.ruleGroups.contains(where: { $0.url == synced.url && ($0.appliesTo ?? .allApps) == scope }) else { return nil }
            var group = RuleGroup(id: synced.id, name: synced.name, summary: synced.summary, url: synced.url,
                                  catalogID: synced.catalogID, isEnabled: synced.isEnabled, format: synced.format, appliesTo: synced.appliesTo)
            group.lastAttempt = nil
            return group
        }
        if let theirs = remote.adDomains, remote.device != deviceID, !deletedHere.contains(RuleGroup.adDomainsID) {
            let mine = state.adDomains
            if theirs.modifiedAt > (mine?.modifiedAt ?? .distantPast) {
                var group = mine ?? RuleGroup.adDomains()
                group.isEnabled = theirs.isEnabled
                group.appliesTo = theirs.appliesTo ?? group.appliesTo
                group.rules = theirs.rules
                group.modifiedAt = theirs.modifiedAt
                groupsToSave.append(group)
            }
        }
        let groupsToDelete = state.ruleGroups.filter { remote.deleted[$0.id] != nil }.map(\.id)
        let removals = rulesToDelete.count + profilesToDelete.count + groupsToDelete.count
        if !force, SyncSafety.needsConfirmation(removing: removals, of: localIDs(state).count) {
            pause(.wouldRemoveHere(removals))
            return
        }

        applyingRemote = true
        defer { applyingRemote = false }
        if !rulesToSave.isEmpty { await model.perform(.saveRules(rulesToSave)) }
        if !rulesToDelete.isEmpty { await model.perform(.deleteRules(rulesToDelete)) }
        for profile in profilesToSave { await model.perform(.saveProfile(profile)) }
        for id in profilesToDelete { await model.perform(.deleteProfile(id)) }
        for group in groupsToSave { await model.perform(.saveRuleGroup(group)) }
        for id in groupsToDelete { await model.perform(.deleteRuleGroup(id)) }
        setBaseline(localIDs(model.state))
        lastSynced = Date()
    }

    // MARK: Large removals

    private func pause(_ conflict: Conflict) {
        guard self.conflict == nil else { return }
        self.conflict = conflict
        model?.notifier.post(id: "argus-sync-paused", title: "iCloud sync is paused",
                             body: "Syncing would remove a lot of rules at once. Open Argus Settings › General to decide.")
    }

    /// This Mac's configuration wins: what it doesn't have is removed everywhere, and what it has
    /// stays (clearing iCloud's deletions of it).
    func keepThisMac() {
        conflict = nil
        upload(force: true)
    }

    /// iCloud wins: for removals here, they're applied; for removals elsewhere, the items come back.
    func useICloud() async {
        let restoring = conflict.map { if case .wouldRemoveElsewhere = $0 { true } else { false } } ?? false
        conflict = nil
        await pull(force: true, restoring: restoring)
        upload()
    }
}
