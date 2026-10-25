import AppKit
import ArgusKit
import Foundation
import Observation
import UserNotifications

enum SidebarItem: String, Hashable, CaseIterable, Identifiable {
    case overview, monitor, map, rules, blocklists, profiles, security, capture

    var id: String { rawValue }

    var title: String {
        switch self {
        case .overview: "Overview"
        case .monitor: "Network Monitor"
        case .map: "World Map"
        case .rules: "Rules"
        case .blocklists: "Blocklists"
        case .profiles: "Profiles"
        case .security: "Security"
        case .capture: "Traffic Capture"
        }
    }

    var symbol: String {
        switch self {
        case .overview: "eye"
        case .monitor: "waveform.path.ecg"
        case .map: "globe.europe.africa"
        case .rules: "list.bullet.rectangle"
        case .blocklists: "shield.lefthalf.filled"
        case .profiles: "person.2.crop.square.stack"
        case .security: "checkmark.seal"
        case .capture: "record.circle"
        }
    }
}

/// Everything the user interface shows, mirrored from the firewall engine.
@MainActor @Observable
final class AppModel {
    enum Engine: Equatable {
        case starting
        /// Connected to the network extension: connections are enforced.
        case filter
        /// Running the in-app monitor: connections are only observed.
        case monitor
    }

    // Engine
    private(set) var engine: Engine = .starting
    private(set) var hello: ServerHello?

    // Configuration
    private(set) var state = FirewallState()

    // Activity
    private(set) var processes: [String: ProcessRecord] = [:]
    private(set) var connections: [String: ConnectionRecord] = [:]
    private(set) var log: [FlowLogEntry] = []
    private(set) var events: [ActivityEvent] = []
    private(set) var today = DailyCounters(day: "")
    private(set) var recentTraffic: [TrafficBucket] = []
    private(set) var processRates: [String: Rate] = [:]
    private(set) var bpfUsers: [BPFUser] = []
    private(set) var captures: [CaptureSession] = []

    // Interaction
    private(set) var alerts: [ConnectionAlert] = []
    var networkPrompt: NetworkIdentity?
    var errorMessage: String?
    private(set) var isUnlocked = false
    private(set) var refreshingGroups: Set<UUID> = []

    // Navigation
    var section: SidebarItem? = DebugLaunch.section ?? .overview
    var selectedProcessPath: String?
    var ruleSearch = ""

    let filter = FilterManager()
    let geo = GeoLocator()
    let network = NetworkWatcher()

    @ObservationIgnored private var client: ArgusClient?
    @ObservationIgnored private var monitor: MonitorEngine?
    @ObservationIgnored private var revision: UInt64 = 0
    @ObservationIgnored private var tasks: [Task<Void, Never>] = []
    @ObservationIgnored private var stateRefresh: Task<Void, Never>?
    @ObservationIgnored private var filterRetry: Task<Void, Never>?
    /// DEBUG sample alerts, kept when reconnecting replaces the real ones.
    @ObservationIgnored private var sampleAlertIDs: Set<UUID> = []
    @ObservationIgnored var onAlertsChanged: (() -> Void)?

    // MARK: - Lifecycle

    func start() async {
        await filter.refresh()
        filter.updateIfNeeded()
        await geo.load()
        if DebugLaunch.downloadLocation, !geo.isReady { Task { await geo.update() } }
        network.onChange = { [weak self] identity in
            Task { await self?.networkChanged(identity) }
        }
        network.start()
        await connect()
        filter.onStatusChange = { [weak self] status in
            Task { await self?.filterStatusChanged(status) }
        }
    }

    func shutdown() {
        tasks.forEach { $0.cancel() }
        monitor?.stop()
    }

    /// Connects to the network filter if it's running, otherwise starts the built-in monitor.
    func connect() async {
        filterRetry?.cancel()
        filterRetry = nil
        if filter.status == .enabled, let name = filter.machServiceName {
            if let client = await connectToFilter(name) {
                await useFilter(client)
                return
            }
            // Just installed, or restarting after an update: watch with the monitor meanwhile.
            retryFilter(name)
        }
        if engine != .monitor || client == nil { await useMonitor() }
    }

    private func useFilter(_ client: ArgusClient) async {
        let previousMonitor = monitor
        await attach(client, engine: .filter)
        if let previousMonitor {
            await migrate(from: previousMonitor)
            previousMonitor.stop()
        }
        monitor = nil
    }

    private func useMonitor() async {
        if monitor == nil {
            let engine = MonitorEngine()
            engine.start()
            monitor = engine
        }
        await attach(monitor!.makeClient(), engine: .monitor)
    }

    private func retryFilter(_ machServiceName: String) {
        filterRetry = Task {
            // Clear the handle when giving up (e.g. the filter was switched off) so turning it
            // back on starts a fresh attempt. A cancelled task has already been replaced.
            defer { if !Task.isCancelled { filterRetry = nil } }
            var delay = Duration.seconds(2)
            while !Task.isCancelled, filter.status == .enabled {
                try? await Task.sleep(for: delay)
                guard !Task.isCancelled else { return }
                if let client = await connectToFilter(machServiceName) {
                    filterRetry = nil
                    await useFilter(client)
                    return
                }
                delay = min(delay * 2, .seconds(30))
            }
        }
    }

    /// Follows the filter wherever it was installed, enabled or removed from.
    private func filterStatusChanged(_ status: FilterManager.Status) async {
        let wantsFilter = status == .enabled
        // A retry already in progress will pick up a filter that's still starting.
        guard wantsFilter != (engine == .filter), !(wantsFilter && filterRetry != nil) else { return }
        await connect()
    }

    private func connectToFilter(_ machServiceName: String) async -> ArgusClient? {
        let requirement = CodeSignature.ownTeamIdentifier.map(ArgusPaths.teamRequirement)
        let client = ArgusClient(channel: XPCChannel.connect(machServiceName: machServiceName, serverRequirement: requirement))
        client.start()
        let hello = Task { try await client.hello(ClientHello(role: .app, wantsAlerts: true)) }
        let timeout = Task {
            // Cancelled when the filter answers in time; only give up if the sleep ran out.
            guard (try? await Task.sleep(for: .seconds(3))) != nil else { return }
            hello.cancel()
            client.close()
        }
        defer { timeout.cancel() }
        guard (try? await hello.value) != nil else {
            client.close()
            return nil
        }
        return client
    }

    private func attach(_ newClient: ArgusClient, engine newEngine: Engine) async {
        tasks.forEach { $0.cancel() }
        tasks = []
        client?.close()
        client = newClient
        revision = 0
        // The filter client is already started (its hello was the reachability check).
        newClient.start { [weak self] in
            Task { @MainActor in self?.connectionLost(newClient) }
        }
        do {
            hello = try await newClient.hello(ClientHello(role: .app, wantsAlerts: true))
            state = try await newClient.state()
            alerts = try await newClient.pendingAlerts() + alerts.filter { sampleAlertIDs.contains($0.id) }
            engine = newEngine
            onAlertsChanged?()
        } catch {
            errorMessage = error.localizedDescription
        }
        await refreshActivity()
        await refreshCaptures()
        tasks.append(Task { [weak self] in
            for await event in newClient.events {
                self?.handle(event)
            }
        })
        tasks.append(Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                await self?.refreshActivity()
            }
        })
        if let identity = network.current { await networkChanged(identity) }
    }

    private func connectionLost(_ lost: ArgusClient) {
        guard lost === client else { return }
        client = nil
        alerts = []
        onAlertsChanged?()
        // The filter may be restarting after an update; try again shortly.
        Task {
            try? await Task.sleep(for: .seconds(2))
            await filter.refresh()
            await connect()
        }
    }

    /// Carries rules made in monitor mode over to the filter the first time it runs.
    private func migrate(from monitor: MonitorEngine) async {
        let key = "migratedMonitorRules"
        guard !UserDefaults.standard.bool(forKey: key),
              case .data(let backup) = await monitor.core.handle(.exportBackup, client: ClientContext(userID: getuid(), pid: getpid(), role: .app), authorization: nil)
        else { return }
        if await perform(.importBackup(backup, merge: true)) != nil {
            UserDefaults.standard.set(true, forKey: key)
        }
    }

    // MARK: - Engine events

    private func handle(_ event: ArgusEvent) {
        switch event {
        case .alert(let alert):
            guard !alerts.contains(where: { $0.id == alert.id }) else { return }
            alerts.append(alert)
            onAlertsChanged?()
        case .alertResolved(let id):
            alerts.removeAll { $0.id == id }
            onAlertsChanged?()
        case .stateChanged:
            scheduleStateRefresh()
        case .notice(let event):
            if !events.contains(where: { $0.id == event.id }) { events.append(event) }
            if event.isWarning { notify(event) }
        }
    }

    private func scheduleStateRefresh() {
        guard stateRefresh == nil else { return }
        stateRefresh = Task {
            try? await Task.sleep(for: .milliseconds(150))
            if let client, let newState = try? await client.state() { state = newState }
            stateRefresh = nil
        }
    }

    private func refreshActivity() async {
        guard let client, let snapshot = try? await client.activity(since: revision) else { return }
        if snapshot.isFull {
            processes = Dictionary(snapshot.processes.map { ($0.id, $0) }, uniquingKeysWith: { _, b in b })
            connections = Dictionary(snapshot.connections.map { ($0.id, $0) }, uniquingKeysWith: { _, b in b })
            log = snapshot.log
            events = snapshot.events
        } else {
            if !snapshot.processes.isEmpty {
                var updated = processes
                for process in snapshot.processes { updated[process.id] = process }
                processes = updated
            }
            if !snapshot.connections.isEmpty {
                var updated = connections
                for connection in snapshot.connections { updated[connection.id] = connection }
                connections = updated
            }
            if !snapshot.log.isEmpty { log = Array((log + snapshot.log).suffix(1000)) }
            if !snapshot.events.isEmpty { events = Array((events + snapshot.events.filter { e in !events.contains { $0.id == e.id } }).suffix(500)) }
        }
        revision = snapshot.revision
        if today != snapshot.today { today = snapshot.today }
        recentTraffic = snapshot.recentTraffic
        processRates = snapshot.processRates
        if bpfUsers != snapshot.bpfUsers { bpfUsers = snapshot.bpfUsers }
        if captures.contains(where: \.isActive) { await refreshCaptures() }
    }

    func refreshCaptures() async {
        guard let client, let list = try? await client.captures() else { return }
        captures = list
    }

    // MARK: - Requests

    /// Sends a request; surfaces errors and handles the settings lock. Returns nil on failure.
    @discardableResult
    func perform(_ request: ArgusRequest) async -> ArgusResponse? {
        guard let client else {
            errorMessage = "Argus isn't connected to its engine yet."
            return nil
        }
        do {
            let response = try await client.call(request)
            if case .state(let newState) = response { state = newState }
            return response
        } catch ArgusError.locked {
            guard !isUnlocked, await unlock() else {
                errorMessage = ArgusError.locked.errorDescription
                return nil
            }
            return await perform(request)
        } catch {
            errorMessage = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            return nil
        }
    }

    /// Asks for an administrator so locked settings can be changed until `lock()`.
    @discardableResult
    func unlock() async -> Bool {
        do {
            let authorization = try await Task.detached { try AdminAuthorization.obtain() }.value
            client?.authorization = authorization
            isUnlocked = true
            return true
        } catch {
            if case AdminAuthorization.Failure.denied = error { errorMessage = error.localizedDescription }
            return false
        }
    }

    func lock() {
        client?.authorization = nil
        isUnlocked = false
    }

    var isLocked: Bool { state.settings.lockEnabled && !isUnlocked }

    // MARK: - Actions

    func setMode(_ mode: FilterMode) async { await perform(.setMode(mode)) }

    func setProtection(_ enabled: Bool) async { await perform(.setProtection(enabled)) }

    /// Allows everything for `minutes` (nil: until resumed). Protection comes back by itself.
    func pause(minutes: Int?) async {
        let until = minutes.map { Date().addingTimeInterval(TimeInterval($0 * 60)) } ?? .distantFuture
        await perform(.pauseProtection(until: until))
    }

    func resume() async { await perform(.pauseProtection(until: nil)) }

    /// When an active pause ends; nil when not paused.
    var pausedUntil: Date? { state.settings.isPaused() ? state.settings.pausedUntil : nil }

    /// Whether Argus is currently letting everything through.
    var isAsleep: Bool { !state.settings.protectionEnabled || pausedUntil != nil }

    /// The latest denial per program and destination, newest first.
    var recentlyBlocked: [FlowLogEntry] {
        var seen = Set<String>()
        return log.reversed().filter { entry in
            entry.verdict.action == .deny && seen.insert("\(entry.processPath)|\(entry.remote)").inserted
        }
    }

    /// Allows what a log entry shows was blocked, for its program or for every program.
    func allow(_ entry: FlowLogEntry, forAllApps: Bool) async {
        let remote: RemoteMatch = if entry.remote != "unknown", IPAddress(entry.remote) == nil {
            .host(entry.remote)
        } else {
            .address(entry.address ?? entry.remote)
        }
        let identity = processes[entry.processPath]?.identity
        let rule = Rule(
            action: .allow,
            process: forAllApps ? .any : .path(entry.processPath),
            codeRequirement: forAllApps ? nil : identity?.designatedRequirement,
            remote: remote,
            direction: entry.direction == .incoming ? .incoming : .outgoing,
            notes: "Allowed from Recently Blocked. It had been blocked by: \(entry.verdict.reason.explanation(in: state))")
        _ = await save(rule)
    }

    func updateSettings(_ change: (inout FirewallSettings) -> Void) async {
        var settings = state.settings
        change(&settings)
        await perform(.updateSettings(settings))
    }

    func save(_ rule: Rule) async -> Bool { await perform(.saveRule(rule)) != nil }

    func deleteRules(_ ids: some Collection<UUID>) async { await perform(.deleteRules(Array(ids))) }

    func setRules(_ ids: some Collection<UUID>, enabled: Bool) async { await perform(.setRulesEnabled(Array(ids), enabled)) }

    /// One-click rule from a monitor row: this program, this server, this port.
    func quickRule(_ action: RuleAction, for connection: ConnectionRecord, wholeDomain: Bool = false, anyProcess: Bool = false) async {
        let remote: RemoteMatch = if let host = connection.hostname, connection.hostnameSource != .reverseLookup {
            wholeDomain ? .domain(DomainName.registrableDomain(of: host) ?? host) : .host(host)
        } else if let address = connection.addresses.first {
            .address(address)
        } else {
            .any
        }
        let identity = processes[connection.processPath]?.identity
        let rule = Rule(
            action: action,
            process: anyProcess ? .any : .path(connection.processPath),
            codeRequirement: anyProcess ? nil : identity?.designatedRequirement,
            remote: remote,
            ports: wholeDomain ? .any : .single(connection.port),
            proto: wholeDomain ? .any : connection.proto == .tcp ? .tcp : connection.proto == .udp ? .udp : .any,
            direction: connection.direction == .incoming ? .incoming : .outgoing)
        _ = await save(rule)
    }

    func save(_ profile: Profile) async { await perform(.saveProfile(profile)) }
    func deleteProfile(_ id: UUID) async { await perform(.deleteProfile(id)) }
    func activateProfile(_ id: UUID?) async { await perform(.activateProfile(id)) }

    func assign(_ network: NetworkIdentity, to profileID: UUID?) async {
        await perform(.assignNetwork(network, profileID: profileID))
        if networkPrompt == network { networkPrompt = nil }
        scheduleStateRefresh()
    }

    private func networkChanged(_ identity: NetworkIdentity) async {
        guard client != nil, case .network(let report)? = await perform(.reportNetwork(identity)) else { return }
        networkPrompt = !report.isKnown && !state.profiles.isEmpty ? identity : nil
    }

    func save(_ group: RuleGroup) async { await perform(.saveRuleGroup(group)) }
    func deleteGroup(_ id: UUID) async { await perform(.deleteRuleGroup(id)) }

    func refreshGroups(_ ids: [UUID]?) async {
        let targets = ids ?? state.ruleGroups.filter { $0.url != nil }.map(\.id)
        refreshingGroups.formUnion(targets)
        await perform(.refreshRuleGroups(targets))
        refreshingGroups.subtract(targets)
    }

    func subscribe(to entry: CatalogEntry) async {
        let group = RuleGroup(name: entry.displayName, summary: entry.summary, url: entry.url, catalogID: entry.id, format: entry.format)
        refreshingGroups.insert(group.id)
        await perform(.saveRuleGroup(group))
        await perform(.refreshRuleGroups([group.id]))
        refreshingGroups.remove(group.id)
    }

    func subscribe(url: URL, name: String, format: BlocklistFormat) async {
        let group = RuleGroup(name: name, url: url, format: format)
        refreshingGroups.insert(group.id)
        await perform(.saveRuleGroup(group))
        await perform(.refreshRuleGroups([group.id]))
        refreshingGroups.remove(group.id)
    }

    func importGroup(from url: URL) async {
        guard let data = try? Data(contentsOf: url) else {
            errorMessage = "Couldn't read \(url.lastPathComponent)."
            return
        }
        await perform(.importRuleGroup(name: url.deletingPathExtension().lastPathComponent, contents: data, format: .automatic))
    }

    func exportRules(_ rules: [Rule], name: String, to url: URL) {
        do {
            try BlocklistParser.exportRuleGroup(name: name, description: "Exported from Argus", rules: rules).write(to: url)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    /// Answers an alert, and optionally others from the same app with the same kind of answer
    /// (a whole-domain answer becomes each alert's own domain).
    func resolve(_ alert: ConnectionAlert, with decision: AlertDecision, alsoAnswering others: [ConnectionAlert] = []) async {
        let answered = Set([alert.id] + others.map(\.id))
        alerts.removeAll { answered.contains($0.id) }
        onAlertsChanged?()
        await send(decision, to: alert)
        for other in others {
            var adapted = decision
            switch decision.remoteScope {
            case .host, .address: adapted.remoteScope = other.hostname == nil ? .address : .host
            case .domain: adapted.remoteScope = .domain(other.suggestedDomain ?? other.hostname ?? "")
            case .any, .localNetwork: break
            }
            await send(adapted, to: other)
        }
    }

    private func send(_ decision: AlertDecision, to alert: ConnectionAlert) async {
        guard let client else { return }
        do {
            try await client.call(.resolveAlert(alert.id, decision))
        } catch ArgusError.notFound {
            // Timed out while the user was deciding, or covered by a rule made a moment ago.
        } catch ArgusError.locked {
            await perform(.resolveAlert(alert.id, decision))
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    /// Tells the engine an alert is on screen so its countdown starts now, not when it was queued.
    func alertShown(_ alert: ConnectionAlert) async {
        let countdownEnds = Date().addingTimeInterval(state.settings.alertTimeout)
        if let index = alerts.firstIndex(where: { $0.id == alert.id }), (alerts[index].deadline ?? .distantFuture) > countdownEnds {
            alerts[index].deadline = countdownEnds
        }
        guard let client, case .alerts(let updated)? = try? await client.call(.alertShown(alert.id)), let fresh = updated.first,
              let index = alerts.firstIndex(where: { $0.id == fresh.id }) else { return }
        alerts[index].deadline = fresh.deadline
    }

    #if DEBUG
    /// Shows a sample alert so the alert window can be designed without the network filter.
    func showSampleAlert() {
        let process = CodeSignature.identity(path: "/Applications/Safari.app/Contents/MacOS/Safari")
        let context = FlowContext(process: process, hostname: "telemetry.example-analytics.com", address: IPAddress("93.184.216.34"), remotePort: 443)
        let advice = Advisor.advise(context, state: state, references: [], history: DomainHistory(otherAppsUsing: ["Mail", "Notes", "Music"]))
        let id = UUID()
        sampleAlertIDs.insert(id)
        alerts.append(ConnectionAlert(
            id: id, createdAt: Date(), deadline: Date().addingTimeInterval(state.settings.alertTimeout), process: process, via: nil,
            pid: 1, userID: getuid(), hostname: "telemetry.example-analytics.com", address: "93.184.216.34", port: 443, proto: .tcp,
            direction: .outgoing, pendingConnections: 3, signatureWarning: nil, advice: advice))
        onAlertsChanged?()
    }
    #endif

    func startCapture(_ request: CaptureRequest) async {
        await perform(.startCapture(request))
        await refreshCaptures()
    }

    func stopCapture(_ id: UUID) async {
        await perform(.stopCapture(id))
        await refreshCaptures()
    }

    func deleteCapture(_ id: UUID) async {
        await perform(.deleteCapture(id))
        await refreshCaptures()
    }

    func saveCapture(_ id: UUID, to url: URL) async -> Bool {
        guard case .data(let data)? = await perform(.fetchCapture(id)) else { return false }
        do {
            try data.write(to: url)
            return true
        } catch {
            errorMessage = error.localizedDescription
            return false
        }
    }

    func exportBackup(to url: URL) async {
        guard case .data(let data)? = await perform(.exportBackup) else { return }
        do { try data.write(to: url) } catch { errorMessage = error.localizedDescription }
    }

    func importBackup(from url: URL, merge: Bool) async {
        guard let data = try? Data(contentsOf: url) else {
            errorMessage = "Couldn't read \(url.lastPathComponent)."
            return
        }
        await perform(.importBackup(data, merge: merge))
    }

    func clearActivity() async {
        await perform(.clearActivity)
        revision = 0
        await refreshActivity()
    }

    // MARK: - Derived data

    var isEnforcing: Bool { engine == .filter }

    var currentRate: Rate {
        let recent = recentTraffic.suffix(3)
        guard !recent.isEmpty else { return .zero }
        let count = Double(recent.count)
        return Rate(bytesInPerSecond: Double(recent.reduce(0) { $0 + $1.bytesIn }) / count,
                    bytesOutPerSecond: Double(recent.reduce(0) { $0 + $1.bytesOut }) / count)
    }

    func connections(of path: String) -> [ConnectionRecord] {
        connections.values.filter { $0.processPath == path }.sorted { $0.lastSeen > $1.lastSeen }
    }

    func rules(for path: String) -> [Rule] {
        state.rules.filter { $0.process == .path(path) }
    }

    func rule(id: UUID?) -> Rule? {
        guard let id else { return nil }
        return state.rules.first { $0.id == id } ?? state.ruleGroups.lazy.flatMap(\.rules).first { $0.id == id }
    }

    func identity(for path: String) -> ProcessIdentity {
        processes[path]?.identity ?? ProcessIdentity(path: path)
    }

    var unapprovedCount: Int { processes.values.reduce(0) { $0 + ($1.unapprovedCount > 0 ? 1 : 0) } }

    var warningEvents: [ActivityEvent] { events.filter(\.isWarning).reversed() }

    // MARK: - Notifications

    private func notify(_ event: ActivityEvent) {
        guard UserDefaults.standard.object(forKey: "notifyWarnings") as? Bool ?? true else { return }
        let content = UNMutableNotificationContent()
        content.title = event.title
        content.body = event.detail
        content.sound = .default
        let request = UNNotificationRequest(identifier: "argus-\(event.id)", content: content, trigger: nil)
        Task {
            let center = UNUserNotificationCenter.current()
            guard (try? await center.requestAuthorization(options: [.alert, .sound])) == true else { return }
            try? await center.add(request)
        }
    }
}
