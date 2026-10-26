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

    private(set) var lastSynced: Date?
    private(set) var problem: String?

    @ObservationIgnored private weak var model: AppModel?
    @ObservationIgnored private var observer: NSObjectProtocol?
    @ObservationIgnored private var pendingUpload: Task<Void, Never>?
    @ObservationIgnored private var applyingRemote = false

    static let key = "argus.configuration.v1"
    private static let enabledKey = "iCloudSync"
    private static let syncedIDsKey = "iCloudSyncedIDs"

    var isEnabled: Bool { UserDefaults.standard.bool(forKey: CloudSync.enabledKey) }

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
    }

    struct Payload: Codable {
        var device: String
        var updated: Date
        var rules: [Rule]
        var profiles: [Profile]
        var groups: [SyncedGroup]
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
        guard enabled, availability == .available else { return }
        NSUbiquitousKeyValueStore.default.synchronize()
        Task {
            await pull()
            upload()
        }
    }

    /// The configuration changed on this Mac.
    func localChanged() {
        guard isEnabled, !applyingRemote, availability == .available else { return }
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
        Set(state.rules.filter(CloudSync.syncable).map(\.id) + state.profiles.map(\.id) + state.ruleGroups.filter { $0.url != nil }.map(\.id))
    }

    private func upload() {
        guard let model else { return }
        let state = model.state
        let remote = readRemote()
        let now = Date()
        let present = localIDs(state)
        var deleted = remote?.deleted ?? [:]
        for id in syncedIDs.subtracting(present) where deleted[id] == nil { deleted[id] = now } // deleted here since the last sync
        for id in present { deleted[id] = nil }
        deleted = deleted.filter { now.timeIntervalSince($0.value) < 60 * 86_400 }
        let payload = Payload(
            device: deviceID, updated: now,
            rules: state.rules.filter(CloudSync.syncable),
            profiles: state.profiles,
            groups: state.ruleGroups.compactMap { group in
                group.url.map { SyncedGroup(id: group.id, name: group.name, summary: group.summary, url: $0, catalogID: group.catalogID,
                                            isEnabled: group.isEnabled, format: group.format) }
            },
            deleted: deleted)
        syncedIDs = present
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
    func pull() async {
        guard isEnabled, availability == .available, let model, let remote = readRemote() else { return }
        let state = model.state
        let deletedHere = syncedIDs.subtracting(localIDs(state)) // don't resurrect what this Mac just deleted
        func same(_ a: Rule, _ b: Rule) -> Bool {
            var a = a, b = b
            a.modifiedAt = .distantPast
            b.modifiedAt = .distantPast
            return a == b
        }

        var rulesToSave: [Rule] = []
        for rule in remote.rules where !deletedHere.contains(rule.id) {
            if let mine = state.rules.first(where: { $0.id == rule.id }) {
                if !same(mine, rule), rule.modifiedAt > mine.modifiedAt { rulesToSave.append(rule) }
            } else {
                rulesToSave.append(rule)
            }
        }
        let rulesToDelete = state.rules.filter { rule in remote.deleted[rule.id].map { rule.modifiedAt < $0 } ?? false }.map(\.id)
        let profilesToSave = remote.profiles.filter { profile in
            !deletedHere.contains(profile.id) && state.profile(id: profile.id) != profile && remote.device != deviceID
        }
        let profilesToDelete = state.profiles.filter { remote.deleted[$0.id] != nil }.map(\.id)
        let groupsToSave: [RuleGroup] = remote.groups.compactMap { synced in
            guard !deletedHere.contains(synced.id) else { return nil }
            if var mine = state.ruleGroup(id: synced.id) {
                guard mine.isEnabled != synced.isEnabled || mine.name != synced.name, remote.device != deviceID else { return nil }
                mine.isEnabled = synced.isEnabled
                mine.name = synced.name
                return mine
            }
            guard !state.ruleGroups.contains(where: { $0.url == synced.url }) else { return nil }
            var group = RuleGroup(id: synced.id, name: synced.name, summary: synced.summary, url: synced.url,
                                  catalogID: synced.catalogID, isEnabled: synced.isEnabled, format: synced.format)
            group.lastAttempt = nil
            return group
        }
        let groupsToDelete = state.ruleGroups.filter { remote.deleted[$0.id] != nil }.map(\.id)

        applyingRemote = true
        defer { applyingRemote = false }
        if !rulesToSave.isEmpty { await model.perform(.saveRules(rulesToSave)) }
        if !rulesToDelete.isEmpty { await model.perform(.deleteRules(rulesToDelete)) }
        for profile in profilesToSave { await model.perform(.saveProfile(profile)) }
        for id in profilesToDelete { await model.perform(.deleteProfile(id)) }
        for group in groupsToSave { await model.perform(.saveRuleGroup(group)) }
        for id in groupsToDelete { await model.perform(.deleteRuleGroup(id)) }
        syncedIDs = localIDs(model.state)
        lastSynced = Date()
    }
}
