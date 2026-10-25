import Foundation

public protocol FirewallCoreDelegate: AnyObject, Sendable {
    /// Shows an alert to an interactive client. Returns false when nobody can answer.
    func firewallCore(_ core: FirewallCore, present alert: ConnectionAlert) -> Bool
    func firewallCore(_ core: FirewallCore, broadcast event: ArgusEvent)
}

public struct ClientContext: Sendable {
    public var userID: UInt32
    public var pid: Int32
    public var role: ClientRole

    public init(userID: UInt32, pid: Int32, role: ClientRole) {
        self.userID = userID
        self.pid = pid
        self.role = role
    }

    public var isRoot: Bool { userID == 0 }
}

public enum FlowDecision: Sendable, Equatable {
    case allow(Verdict)
    case deny(Verdict)
    /// Held for an alert; the resume handler passed to `decide` will be called later.
    case pause(alertID: UUID)
}

/// The firewall engine. It runs inside the network extension when installed, or inside the
/// app as a monitor otherwise; the hosting process feeds it connections and serves its
/// requests to clients.
public final class FirewallCore: @unchecked Sendable {
    public let host: EngineHost
    public let store: StateStore
    public let activity = ActivityTracker()
    public let captures: CaptureManager

    /// Checks a process against a rule's stored code requirement. Replaceable for tests.
    public var requirementChecker: @Sendable (String, FlowContext) -> Bool = { requirement, ctx in
        CodeSignature.satisfies(requirement: requirement, auditToken: ctx.auditToken, pid: ctx.pid)
    }

    /// Lists programs reading /dev/bpf. nil disables packet-capture monitoring.
    public var bpfScanner: (@Sendable () -> [BPFUser])? = { ProcessLookup.bpfUsers() }

    private let queue = DispatchQueue(label: "com.argus.core", qos: .utility)
    private var timer: DispatchSourceTimer?
    private let delegateBox = Locked<WeakDelegate>(WeakDelegate())
    private let exitWatchers = Locked<[Int32: DispatchSourceProcess]>([:])
    private let inFlight = Locked<[UUID: Task<Void, Never>]>([:])
    /// Reference lists for advice, by `ReferenceList.id`.
    private let references = Locked<[String: CompiledBlocklist]>([:])
    private let referenceRefresh = Locked<(running: Bool, lastAttempt: Date)>((false, .distantPast))

    private struct WeakDelegate { weak var value: FirewallCoreDelegate? }

    private struct Waiter {
        var flowID: UUID?
        var context: FlowContext
        var resume: @Sendable (Verdict) -> Void
    }

    private struct PendingAlert {
        var alert: ConnectionAlert
        var key: String
        var waiters: [Waiter]
    }

    private struct Inner {
        var state: FirewallState
        var compiled = CompiledRuleSet()
        var blocklists: [UUID: CompiledBlocklist] = [:]
        var pending: [UUID: PendingAlert] = [:]
        var pendingByKey: [String: UUID] = [:]
        var dns = DNSCache()
        var saveScheduled = false
        var warnedInvalidSignatures: Set<String> = []
        var lastActivitySave = Date()
        var lastBPFScan = Date.distantPast
    }

    private let inner: Locked<Inner>
    private let bootSession = SystemInfo.bootSessionID

    public init(host: EngineHost, directory: URL) {
        self.host = host
        store = StateStore(directory: directory)
        captures = CaptureManager(directory: store.capturesDirectory)
        var state = store.loadState() ?? FirewallState.initial()
        let boot = bootSession
        state.rules.removeAll { rule in
            if case .untilRestart(let session) = rule.expiration { return session != boot }
            if case .untilQuit(let pid, let start) = rule.expiration { return ProcessLookup.startTime(pid: pid) != start }
            return false
        }
        var initial = Inner(state: state)
        for group in state.ruleGroups {
            if let list = store.loadBlocklist(group.id) { initial.blocklists[group.id] = list }
        }
        FirewallCore.recompile(&initial)
        inner = Locked(initial)
        if let data = store.loadActivity() { activity.restore(from: data) }
        for list in BlocklistCatalog.references {
            if let compiled = store.loadReference(list.id) { references.withLock { $0[list.id] = compiled } }
        }
        for rule in state.rules {
            if case .untilQuit(let pid, _) = rule.expiration { watchExit(of: pid) }
        }
    }

    public var delegate: FirewallCoreDelegate? {
        get { delegateBox.withLock { $0.value } }
        set { delegateBox.withLock { $0.value = newValue } }
    }

    /// Starts housekeeping: expiring rules, updating rule groups, BPF scans and saving.
    public func start() {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 2, repeating: 5)
        timer.setEventHandler { [weak self] in self?.tick() }
        timer.resume()
        self.timer = timer
    }

    public func stop() {
        timer?.cancel()
        timer = nil
        flush()
    }

    /// Writes everything to disk now.
    public func flush() {
        let state = inner.withLock { $0.state }
        try? store.saveState(state)
        if let data = activity.persistenceData() { store.saveActivity(data) }
    }

    public var state: FirewallState { inner.withLock { $0.state } }

    // MARK: - Deciding connections

    /// Decides a new connection. When the answer is `.pause`, `resume` is called exactly once later.
    public func decide(flowID: UUID, context: FlowContext, resume: @escaping @Sendable (Verdict) -> Void) -> FlowDecision {
        let ctx = enrich(context)
        if let verdict = evaluate(ctx) {
            activity.recordConnection(flowID: flowID, context: ctx, verdict: verdict)
            return verdict.action == .allow ? .allow(verdict) : .deny(verdict)
        }
        if let alertID = enqueueAlert(flowID: flowID, context: ctx, resume: resume) {
            return .pause(alertID: alertID)
        }
        let verdict = Verdict(state.settings.unattendedAction, .unattended)
        activity.recordConnection(flowID: flowID, context: ctx, verdict: verdict)
        return verdict.action == .allow ? .allow(verdict) : .deny(verdict)
    }

    /// Records a connection the monitor saw after the fact. Returns what Argus would have done.
    @discardableResult
    public func observe(flowID: UUID, context: FlowContext) -> Verdict {
        let ctx = enrich(context)
        var verdict = evaluate(ctx) ?? Verdict(.allow, .observed)
        verdict.isEnforced = false
        activity.recordConnection(flowID: flowID, context: ctx, verdict: verdict)
        return verdict
    }

    public func flowStatistics(_ id: UUID, totalIn: UInt64, totalOut: UInt64, closed: Bool) {
        activity.updateFlow(id, totalIn: totalIn, totalOut: totalOut, closed: closed)
        if closed { captures.endFlow(id) }
    }

    /// Feeds a DNS answer seen on the wire, so later connections by address get a hostname.
    public func ingestDNS(_ payload: Data, overTCP: Bool) {
        let messages = overTCP ? DNSMessage.parseStream(payload) : DNSMessage(payload).map { [$0] } ?? []
        guard !messages.isEmpty else { return }
        inner.withLock { inner in
            guard inner.state.settings.learnHostnamesFromDNS else { return }
            for message in messages { inner.dns.record(message) }
        }
    }

    public func hostname(for address: IPAddress) -> String? {
        inner.withLock { $0.dns.hostname(for: address) }
    }

    private func enrich(_ context: FlowContext) -> FlowContext {
        var ctx = context
        if ctx.hostname == nil, let address = ctx.address, let name = hostname(for: address) {
            ctx.hostname = name
            ctx.hostnameSource = .dns
        }
        if ctx.process.signature == .invalid {
            let isNew = inner.withLock { $0.warnedInvalidSignatures.insert(ctx.process.path).inserted }
            if isNew {
                notice(.invalidSignature, title: "\(ctx.process.name) has an invalid code signature",
                       detail: "The program at \(ctx.process.path) was modified after it was signed. It may have been tampered with.",
                       processPath: ctx.process.path)
            }
        }
        return ctx
    }

    /// The verdict for a connection, or nil when the user should be asked.
    public func evaluate(_ ctx: FlowContext) -> Verdict? {
        let (settings, compiled, mode) = inner.withLock { ($0.state.settings, $0.compiled, $0.state.effectiveMode) }
        let enforced = host.canEnforce
        guard settings.protectionEnabled else { return Verdict(.allow, .protectionOff, enforced: enforced) }
        if settings.isPaused() { return Verdict(.allow, .paused, enforced: enforced) }

        if let match = compiled.evaluate(ctx) {
            if match.action == .allow, settings.enforceCodeSignatures, let rule = match.rule,
               let requirement = rule.codeRequirement, !requirementChecker(requirement, ctx) {
                notice(.signatureMismatch, title: "Blocked \(ctx.process.name): code signature changed",
                       detail: "A rule allows \(ctx.process.path), but the program no longer matches the signature it had when the rule was made. It may have been replaced by malware.",
                       processPath: ctx.process.path)
                return Verdict(.deny, .signatureMismatch(rule.id), enforced: enforced)
            }
            return Verdict(match.action, match.reason, enforced: enforced)
        }
        if ctx.address?.isLoopback == true { return Verdict(.allow, .localNetwork, enforced: enforced) }
        if settings.allowLocalNetwork, ctx.address?.isLocalNetwork == true { return Verdict(.allow, .localNetwork, enforced: enforced) }
        if settings.allowAppleSoftware, ctx.process.signature == .apple { return Verdict(.allow, .appleSoftware, enforced: enforced) }
        if settings.allowSignedSoftware, ctx.process.signature == .appStore || ctx.process.signature == .developerID {
            return Verdict(.allow, .signedSoftware, enforced: enforced)
        }
        switch mode {
        case .silentAllow: return Verdict(.allow, .mode(.silentAllow), enforced: enforced)
        case .silentDeny: return Verdict(.deny, .mode(.silentDeny), enforced: enforced)
        case .alert: return nil
        }
    }

    // MARK: - Alerts

    static func alertKey(_ ctx: FlowContext) -> String {
        "\(ctx.process.path)|\(ctx.remoteDisplay)|\(ctx.rulePort)|\(ctx.proto.rawValue)|\(ctx.direction.rawValue)|\(ctx.userID)"
    }

    /// How long an alert may wait in the queue before anyone has looked at it. Its real
    /// countdown (the alert timeout setting) starts when a client reports it on screen.
    static let queuedAlertLifetime: TimeInterval = 600

    private func enqueueAlert(flowID: UUID, context ctx: FlowContext, resume: @escaping @Sendable (Verdict) -> Void) -> UUID? {
        let key = FirewallCore.alertKey(ctx)
        let waiter = Waiter(flowID: flowID, context: ctx, resume: resume)
        let queuedFor = max(FirewallCore.queuedAlertLifetime, state.settings.alertTimeout)
        let newAlert = ConnectionAlert(
            id: UUID(), createdAt: Date(), deadline: Date().addingTimeInterval(queuedFor), process: ctx.process, via: ctx.via,
            pid: ctx.pid, userID: ctx.userID, hostname: ctx.hostname, address: ctx.address?.description, port: ctx.rulePort,
            proto: ctx.proto, direction: ctx.direction, pendingConnections: 1,
            signatureWarning: ctx.process.signature.isWarning ? "This program is \(ctx.process.signature.displayName.lowercased())." : nil,
            advice: advice(for: ctx))

        // Repeat attempts to the same place join the alert that's already showing.
        let existing: UUID? = inner.withLock { inner in
            if let id = inner.pendingByKey[key], inner.pending[id] != nil {
                inner.pending[id]!.waiters.append(waiter)
                inner.pending[id]!.alert.pendingConnections += 1
                return id
            }
            inner.pending[newAlert.id] = PendingAlert(alert: newAlert, key: key, waiters: [waiter])
            inner.pendingByKey[key] = newAlert.id
            return nil
        }
        if let existing { return existing }

        guard delegate?.firewallCore(self, present: newAlert) == true else {
            // Nobody to ask. The caller handles its own flow; release any that joined meanwhile.
            let joined = removePending(newAlert.id)?.waiters.filter { $0.flowID != flowID } ?? []
            let verdict = Verdict(state.settings.unattendedAction, .unattended)
            for other in joined {
                activity.recordConnection(flowID: other.flowID, context: other.context, verdict: verdict)
                other.resume(verdict)
            }
            return nil
        }
        scheduleExpiry(of: newAlert.id)
        return newAlert.id
    }

    /// Starts an alert's countdown because someone can now see it. Returns the updated alert.
    public func alertShown(_ id: UUID) -> ConnectionAlert? {
        let countdownEnds = Date().addingTimeInterval(state.settings.alertTimeout)
        let alert: ConnectionAlert? = inner.withLock { inner in
            guard var pending = inner.pending[id] else { return nil }
            // Only ever shorten, so a second window showing it doesn't restart the clock.
            pending.alert.deadline = min(pending.alert.deadline ?? countdownEnds, countdownEnds)
            inner.pending[id] = pending
            return pending.alert
        }
        if alert != nil { scheduleExpiry(of: id) }
        return alert
    }

    private func scheduleExpiry(of id: UUID) {
        guard let deadline = inner.withLock({ $0.pending[id]?.alert.deadline }) else { return }
        queue.asyncAfter(deadline: .now() + max(0, deadline.timeIntervalSinceNow)) { [weak self] in
            self?.expireIfDue(id)
        }
    }

    private func expireIfDue(_ id: UUID) {
        guard let deadline = inner.withLock({ $0.pending[id]?.alert.deadline }) else { return }
        if deadline.timeIntervalSinceNow <= 0.5 {
            resolveAlert(id, decision: nil)
        } else {
            scheduleExpiry(of: id)
        }
    }

    private func removePending(_ id: UUID) -> PendingAlert? {
        inner.withLock { inner in
            guard let pending = inner.pending.removeValue(forKey: id) else { return nil }
            if inner.pendingByKey[pending.key] == id { inner.pendingByKey[pending.key] = nil }
            return pending
        }
    }

    public var pendingAlerts: [ConnectionAlert] {
        inner.withLock { $0.pending.values.map(\.alert).sorted { $0.createdAt < $1.createdAt } }
    }

    /// Answers an alert. A nil decision means it timed out.
    @discardableResult
    public func resolveAlert(_ id: UUID, decision: AlertDecision?) -> Bool {
        guard let pending = removePending(id) else { return false }
        let verdict: Verdict
        var createdRule = false
        if let decision {
            if decision.duration != .once, let first = pending.waiters.first {
                let rule = makeRule(from: decision, context: first.context)
                mutate { $0.rules.append(rule) }
                if case .untilQuit(let pid, _) = rule.expiration { watchExit(of: pid) }
                verdict = Verdict(decision.action, .rule(rule.id), enforced: host.canEnforce)
                createdRule = true
            } else {
                verdict = Verdict(decision.action, .alertAnswer, enforced: host.canEnforce)
            }
        } else {
            let settings = state.settings
            let advised = settings.alertTimeoutFollowsAdvice ? pending.alert.advice.flatMap { $0.isConfident ? $0.suggestion : nil } : nil
            verdict = Verdict(advised ?? settings.alertTimeoutAction, .alertTimeout, enforced: host.canEnforce)
        }
        for waiter in pending.waiters {
            activity.recordConnection(flowID: waiter.flowID, context: waiter.context, verdict: verdict)
            waiter.resume(verdict)
        }
        broadcast(.alertResolved(id))
        if createdRule { resolveAlertsCoveredByRules() }
        return true
    }

    /// Lets every held connection through (or not) without asking, e.g. when protection pauses.
    private func releasePendingAlerts(with verdict: Verdict) {
        let all = inner.withLock { inner -> [PendingAlert] in
            defer {
                inner.pending = [:]
                inner.pendingByKey = [:]
            }
            return Array(inner.pending.values)
        }
        for pending in all {
            for waiter in pending.waiters {
                activity.recordConnection(flowID: waiter.flowID, context: waiter.context, verdict: verdict)
                waiter.resume(verdict)
            }
            broadcast(.alertResolved(pending.alert.id))
        }
    }

    /// After a new rule, other waiting alerts may already have their answer.
    private func resolveAlertsCoveredByRules() {
        let candidates = inner.withLock { inner in inner.pending.values.map { ($0.alert.id, $0.waiters.first?.context) } }
        for (id, context) in candidates {
            guard let context, let verdict = evaluate(context), let pending = removePending(id) else { continue }
            for waiter in pending.waiters {
                activity.recordConnection(flowID: waiter.flowID, context: waiter.context, verdict: verdict)
                waiter.resume(verdict)
            }
            broadcast(.alertResolved(id))
        }
    }

    func makeRule(from decision: AlertDecision, context ctx: FlowContext) -> Rule {
        let remote: RemoteMatch = switch decision.remoteScope {
        case .host: ctx.hostname.map(RemoteMatch.host) ?? ctx.address.map { .address($0.description) } ?? .any
        case .domain(let domain): .domain(domain)
        case .address: ctx.address.map { .address($0.description) } ?? .any
        case .localNetwork: .localNetwork
        case .any: .any
        }
        let thisPort = decision.portScope == .thisPort
        let proto: ProtocolMatch = !thisPort ? .any : ctx.proto == .tcp ? .tcp : ctx.proto == .udp ? .udp : .any
        let expiration: RuleExpiration = switch decision.duration {
        case .once, .forever: .never
        case .untilQuit: .untilQuit(pid: ctx.pid, startTime: ctx.processStartTime ?? ProcessLookup.startTime(pid: ctx.pid) ?? 0)
        case .untilRestart: .untilRestart(bootSession: bootSession)
        case .minutes(let minutes): .date(Date().addingTimeInterval(TimeInterval(minutes * 60)))
        }
        let thisProcess = decision.processScope == .thisProcess
        return Rule(
            action: decision.action,
            process: thisProcess ? .path(ctx.process.path) : .any,
            codeRequirement: thisProcess ? ctx.process.designatedRequirement : nil,
            remote: remote,
            ports: thisPort ? .single(ctx.rulePort) : .any,
            proto: proto,
            direction: ctx.direction == .incoming ? .incoming : .outgoing,
            userID: decision.allUsers ? nil : ctx.userID,
            profileID: decision.activeProfileOnly ? state.settings.activeProfileID : nil,
            expiration: expiration,
            origin: .alert)
    }

    // MARK: - Traffic capture hooks

    /// Registers an allowed flow with any capture that wants it. Returns true if its payload should be fed in.
    public func beginCaptureIfWanted(flowID: UUID, context: FlowContext) -> Bool {
        guard captures.isCapturing else { return false }
        let ctx = enrich(context)
        guard captures.wantsFlow(ctx) else { return false }
        captures.beginFlow(flowID, context: ctx)
        return true
    }

    // MARK: - State changes

    @discardableResult
    func mutate(_ body: (inout FirewallState) throws -> Void) rethrows -> FirewallState {
        let state = try inner.withLock { inner -> FirewallState in
            try body(&inner.state)
            inner.state.revision += 1
            FirewallCore.recompile(&inner)
            return inner.state
        }
        scheduleSave()
        broadcast(.stateChanged(revision: state.revision))
        return state
    }

    private static func recompile(_ inner: inout Inner) {
        let groups = inner.state.ruleGroups.filter(\.isEnabled)
        let lists = groups.compactMap { group in inner.blocklists[group.id].map { (group.id, $0) } }
        inner.compiled = CompiledRuleSet(
            rules: inner.state.rules + groups.flatMap(\.rules),
            activeProfile: inner.state.settings.activeProfileID,
            blocklists: lists)
    }

    private func scheduleSave() {
        let shouldSchedule = inner.withLock { inner -> Bool in
            defer { inner.saveScheduled = true }
            return !inner.saveScheduled
        }
        guard shouldSchedule else { return }
        queue.asyncAfter(deadline: .now() + 0.5) { [weak self] in
            guard let self else { return }
            let state = self.inner.withLock { inner -> FirewallState in
                inner.saveScheduled = false
                return inner.state
            }
            try? self.store.saveState(state)
        }
    }

    private func broadcast(_ event: ArgusEvent) {
        delegate?.firewallCore(self, broadcast: event)
    }

    private func notice(_ kind: ActivityEvent.Kind, title: String, detail: String, processPath: String? = nil) {
        let event = activity.addEvent(kind, title: title, detail: detail, processPath: processPath)
        broadcast(.notice(event))
    }

    private func watchExit(of pid: Int32) {
        exitWatchers.withLock { watchers in
            guard watchers[pid] == nil, pid > 0 else { return }
            let source = DispatchSource.makeProcessSource(identifier: pid, eventMask: .exit, queue: queue)
            source.setEventHandler { [weak self] in self?.processExited(pid) }
            source.resume()
            watchers[pid] = source
        }
    }

    private func processExited(_ pid: Int32) {
        exitWatchers.withLock { $0.removeValue(forKey: pid)?.cancel() }
        let affected = state.rules.contains { rule in
            if case .untilQuit(let p, _) = rule.expiration { return p == pid }
            return false
        }
        guard affected else { return }
        mutate { state in
            state.rules.removeAll { rule in
                if case .untilQuit(let p, _) = rule.expiration { return p == pid }
                return false
            }
        }
    }

    // MARK: - Housekeeping

    private func tick() {
        let now = Date()
        if let until = state.settings.pausedUntil, until <= now {
            mutate { $0.settings.pausedUntil = nil }
            notice(.protectionChanged, title: "Protection resumed", detail: "The pause ended; Argus is filtering connections again.")
        }
        let expired = state.rules.filter { rule in
            if case .date(let end) = rule.expiration { return end <= now }
            return false
        }
        if !expired.isEmpty {
            let ids = Set(expired.map(\.id))
            mutate { $0.rules.removeAll { ids.contains($0.id) } }
            for rule in expired { activity.addEvent(.ruleExpired, title: "Temporary rule expired", detail: rule.summary) }
        }

        let due = state.ruleGroups.filter { $0.isDue(now: now) }.map(\.id)
        if !due.isEmpty { Task { await self.refreshRuleGroups(due) } }

        activity.tick(now: now)
        for session in captures.enforceLimits(now: now) {
            notice(.captureFinished, title: "Capture finished", detail: "\(session.processName ?? "All apps"): \(session.packetCount) packets")
        }

        refreshReferencesIfDue(now: now)

        let (scanDue, saveDue): (Bool, Bool) = inner.withLock { inner in
            let scan = inner.state.settings.monitorPacketCapture && now.timeIntervalSince(inner.lastBPFScan) >= 10
            if scan { inner.lastBPFScan = now }
            let save = now.timeIntervalSince(inner.lastActivitySave) >= 120
            if save { inner.lastActivitySave = now }
            inner.dns.prune(now: now)
            return (scan, save)
        }
        if scanDue, let scanner = bpfScanner {
            for user in activity.updateBPFUsers(scanner()) {
                notice(.packetCapture, title: "\(user.name) is reading raw network traffic",
                       detail: "\(user.path) (pid \(user.pid)) opened \(user.device). Packet sniffers can see all unencrypted traffic on this Mac.",
                       processPath: user.path)
            }
        }
        if saveDue, let data = activity.persistenceData() { store.saveActivity(data) }
    }

    // MARK: - Advice

    func advice(for ctx: FlowContext) -> ConnectionAdvice? {
        let state = self.state
        guard state.settings.suggestAnswers else { return nil }
        let loaded = references.withLock { $0 }
        let lists = BlocklistCatalog.references.compactMap { list in loaded[list.id].map { (list, $0) } }
        let history = ctx.hostname.flatMap(DomainName.registrableDomain).map { activity.history(domain: $0, processPath: ctx.process.path) }
        return Advisor.advise(ctx, state: state, references: lists, history: history ?? DomainHistory())
    }

    /// Keeps the advice-only reference lists a day fresh, retrying failures hourly.
    private func refreshReferencesIfDue(now: Date) {
        guard state.settings.suggestAnswers else { return }
        let stale = BlocklistCatalog.references.filter { list in
            store.referenceDate(list.id).map { now.timeIntervalSince($0) > 86_400 } ?? true
        }
        guard !stale.isEmpty else { return }
        let start = referenceRefresh.withLock { r -> Bool in
            guard !r.running, now.timeIntervalSince(r.lastAttempt) > 3600 else { return false }
            r = (true, now)
            return true
        }
        guard start else { return }
        Task {
            for list in stale {
                do {
                    let (data, response) = try await URLSession.shared.data(from: list.url)
                    if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) { continue }
                    let compiled = try BlocklistParser.parse(data, format: .domains, groupID: UUID()).compiled
                    try store.saveReference(compiled, id: list.id)
                    references.withLock { $0[list.id] = compiled }
                } catch {
                    continue
                }
            }
            referenceRefresh.withLock { $0.running = false }
        }
    }

    /// Loads a reference list directly (tests, or a list fetched some other way).
    public func installReference(_ list: CompiledBlocklist, id: String) {
        references.withLock { $0[id] = list }
    }

    // MARK: - Rule groups

    /// Downloads the given groups (all subscriptions when nil). A group that's already
    /// downloading isn't fetched twice; the caller waits for the download in flight.
    public func refreshRuleGroups(_ ids: [UUID]?) async {
        let groups = state.ruleGroups.filter { group in
            group.url != nil && (ids.map { $0.contains(group.id) } ?? true)
        }
        let downloads = groups.map { group in
            inFlight.withLock { flights -> Task<Void, Never> in
                if let running = flights[group.id] { return running }
                let task = Task {
                    await self.refresh(group)
                    _ = self.inFlight.withLock { $0.removeValue(forKey: group.id) }
                }
                flights[group.id] = task
                return task
            }
        }
        for download in downloads { await download.value }
    }

    private func refresh(_ group: RuleGroup) async {
        guard let url = group.url else { return }
        do {
            var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 90)
            request.setValue("Argus/\(ArgusVersion.marketing)", forHTTPHeaderField: "User-Agent")
            let (data, response) = try await URLSession.shared.data(for: request)
            if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
                throw ArgusError.failed("The server answered HTTP \(http.statusCode).")
            }
            try install(data, format: group.format, into: group.id)
        } catch {
            let message = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            mutate { state in
                guard let index = state.ruleGroups.firstIndex(where: { $0.id == group.id }) else { return }
                state.ruleGroups[index].lastAttempt = Date()
                state.ruleGroups[index].lastError = message
            }
            notice(.ruleGroupFailed, title: "Couldn't update “\(group.name)”", detail: message)
        }
    }

    private func install(_ data: Data, format: BlocklistFormat, into id: UUID) throws {
        let parsed = try BlocklistParser.parse(data, format: format, groupID: id)
        let compiled = parsed.compiled
        try store.saveBlocklist(compiled, id: id)
        inner.withLock { $0.blocklists[id] = compiled }
        let state = mutate { state in
            guard let index = state.ruleGroups.firstIndex(where: { $0.id == id }) else { return }
            var group = state.ruleGroups[index]
            group.hostCount = compiled.domains.exact.count
            group.domainCount = compiled.domains.suffix.count
            group.addressCount = parsed.addresses.count
            group.rules = parsed.rules
            group.lastUpdated = Date()
            group.lastAttempt = Date()
            group.lastError = nil
            if group.name.isEmpty, let name = parsed.name { group.name = name }
            if group.summary.isEmpty, let summary = parsed.summary { group.summary = summary }
            state.ruleGroups[index] = group
        }
        if let group = state.ruleGroup(id: id) {
            activity.addEvent(.ruleGroupUpdated, title: "Updated “\(group.name)”", detail: "\(group.entryCount.formatted()) entries")
        }
    }

    // MARK: - Networks

    func handleNetwork(_ identity: NetworkIdentity) -> NetworkReport {
        let current = state
        let matched = current.profiles.first { $0.networks.contains { $0.matches(identity) } }
        let known = matched != nil || current.knownNetworks.contains { $0.matches(identity) }
        var switched = false
        if current.settings.autoSwitchProfiles, let matched, matched.id != current.settings.activeProfileID {
            mutate { $0.settings.activeProfileID = matched.id }
            notice(.profileSwitched, title: "Switched to “\(matched.name)”", detail: "Joined \(identity.displayName).")
            switched = true
        }
        return NetworkReport(profileID: matched?.id, isKnown: known, switched: switched)
    }

    // MARK: - Requests

    public func serverHello(for client: ClientContext) -> ServerHello {
        ServerHello(host: host, version: ArgusVersion.marketing, protocolVersion: ArgusVersion.protocolVersion,
                    clientUserID: client.userID, canCapture: host.canEnforce)
    }

    private func isAuthorized(_ request: ArgusRequest, client: ClientContext, authorization: Data?) -> Bool {
        let settings = state.settings
        guard settings.lockEnabled, request.isMutating, !client.isRoot else { return true }
        if case .resolveAlert = request, settings.alertsAllowedWhenLocked { return true }
        return AdminAuthorization.verify(authorization)
    }

    public func handle(_ request: ArgusRequest, client: ClientContext, authorization: Data?) async -> ArgusResponse {
        guard isAuthorized(request, client: client, authorization: authorization) else { return .error(.locked) }
        do {
            return try await perform(request, client: client)
        } catch let error as ArgusError {
            return .error(error)
        } catch {
            return .error(.failed((error as? LocalizedError)?.errorDescription ?? error.localizedDescription))
        }
    }

    private func perform(_ request: ArgusRequest, client: ClientContext) async throws -> ArgusResponse {
        switch request {
        case .hello:
            return .hello(serverHello(for: client))
        case .getState:
            return .state(state)
        case .getActivity(let since):
            return .activity(activity.snapshot(since: since))
        case .getTraffic(let query):
            return .traffic(activity.traffic(query))

        case .updateSettings(let settings):
            let wasEnabled = state.settings.protectionEnabled
            let newState = mutate { $0.settings = settings }
            if wasEnabled != settings.protectionEnabled { protectionChanged(settings.protectionEnabled) }
            return .state(newState)
        case .setMode(let mode):
            return .state(mutate { $0.settings.mode = mode })
        case .setProtection(let enabled):
            let newState = mutate { $0.settings.protectionEnabled = enabled }
            protectionChanged(enabled)
            return .state(newState)
        case .pauseProtection(let until):
            let pausing = until.map { $0 > Date() } ?? false
            let newState = mutate { $0.settings.pausedUntil = pausing ? until : nil }
            if pausing, let until {
                releasePendingAlerts(with: Verdict(.allow, .paused, enforced: host.canEnforce))
                let minutes = max(1, Int((until.timeIntervalSinceNow / 60).rounded()))
                notice(.protectionChanged, title: "Protection paused",
                       detail: until.timeIntervalSinceNow > 86_400 * 365 ? "Everything is allowed until you resume it."
                           : "Everything is allowed for \(minutes) minute\(minutes == 1 ? "" : "s"); protection resumes by itself.")
            } else {
                notice(.protectionChanged, title: "Protection resumed", detail: "Argus is filtering connections again.")
            }
            return .state(newState)

        case .saveRule(var rule):
            if rule.isFromRuleGroup { throw ArgusError.invalid("Rules from a rule group are managed by its subscription.") }
            if case .address(let text) = rule.remote, IPNetwork(text) == nil { throw ArgusError.invalid("“\(text)” is not an IP address or network.") }
            rule.modifiedAt = Date()
            if client.role == .commandLine, !state.rules.contains(where: { $0.id == rule.id }) { rule.origin = .commandLine }
            let saved = rule
            let newState = mutate { state in
                if let index = state.rules.firstIndex(where: { $0.id == saved.id }) { state.rules[index] = saved } else { state.rules.append(saved) }
            }
            if case .untilQuit(let pid, _) = rule.expiration { watchExit(of: pid) }
            resolveAlertsCoveredByRules()
            return .state(newState)
        case .deleteRules(let ids):
            let set = Set(ids)
            return .state(mutate { $0.rules.removeAll { set.contains($0.id) } })
        case .setRulesEnabled(let ids, let enabled):
            let set = Set(ids)
            return .state(mutate { state in
                for index in state.rules.indices where set.contains(state.rules[index].id) {
                    state.rules[index].isEnabled = enabled
                    state.rules[index].modifiedAt = Date()
                }
            })

        case .saveProfile(let profile):
            return .state(mutate { state in
                if let index = state.profiles.firstIndex(where: { $0.id == profile.id }) { state.profiles[index] = profile } else { state.profiles.append(profile) }
            })
        case .deleteProfile(let id):
            return .state(mutate { state in
                state.profiles.removeAll { $0.id == id }
                state.rules.removeAll { $0.profileID == id }
                if state.settings.activeProfileID == id { state.settings.activeProfileID = nil }
            })
        case .activateProfile(let id):
            if let id, state.profile(id: id) == nil { throw ArgusError.notFound("Profile") }
            let newState = mutate { $0.settings.activeProfileID = id }
            activity.addEvent(.profileSwitched, title: "Switched to “\(newState.activeProfile?.name ?? "No Profile")”")
            return .state(newState)
        case .reportNetwork(let identity):
            return .network(handleNetwork(identity))
        case .assignNetwork(let identity, let profileID):
            mutate { state in
                for index in state.profiles.indices { state.profiles[index].networks.removeAll { $0.matches(identity) } }
                if let profileID, let index = state.profiles.firstIndex(where: { $0.id == profileID }) {
                    state.profiles[index].networks.append(identity)
                }
                if !state.knownNetworks.contains(where: { $0.matches(identity) }) { state.knownNetworks.append(identity) }
            }
            return .network(handleNetwork(identity))

        case .saveRuleGroup(var group):
            let previous = state.ruleGroup(id: group.id)
            if let previous {
                // Contents come from the subscription, not from the client.
                group.rules = previous.rules
                group.hostCount = previous.hostCount
                group.domainCount = previous.domainCount
                group.addressCount = previous.addressCount
                group.lastUpdated = previous.lastUpdated
            }
            let saved = group
            let newState = mutate { state in
                if let index = state.ruleGroups.firstIndex(where: { $0.id == saved.id }) { state.ruleGroups[index] = saved } else { state.ruleGroups.append(saved) }
            }
            if group.url != nil, previous == nil || previous?.url != group.url || (group.isEnabled && group.lastUpdated == nil) {
                Task { await self.refreshRuleGroups([saved.id]) }
            }
            return .state(newState)
        case .deleteRuleGroup(let id):
            store.deleteBlocklist(id)
            inner.withLock { _ = $0.blocklists.removeValue(forKey: id) }
            return .state(mutate { $0.ruleGroups.removeAll { $0.id == id } })
        case .refreshRuleGroups(let ids):
            await refreshRuleGroups(ids)
            return .state(state)
        case .importRuleGroup(let name, let contents, let format):
            let group = RuleGroup(name: name, format: format)
            mutate { $0.ruleGroups.append(group) }
            do {
                try install(contents, format: format, into: group.id)
            } catch {
                mutate { $0.ruleGroups.removeAll { $0.id == group.id } }
                throw error
            }
            return .state(state)

        case .pendingAlerts:
            return .alerts(pendingAlerts)
        case .alertShown(let id):
            return .alerts(alertShown(id).map { [$0] } ?? [])
        case .resolveAlert(let id, let decision):
            guard resolveAlert(id, decision: decision) else { throw ArgusError.notFound("Alert") }
            return .ok

        case .startCapture(let request):
            guard host.canEnforce else {
                throw ArgusError.unsupported("Traffic capture needs the Argus network filter, which isn't installed.")
            }
            let name = request.processPath.map { activity.process($0)?.identity.name ?? ProcessIdentity.defaultName(for: $0) }
            return .capture(try captures.start(request, processName: name))
        case .stopCapture(let id):
            guard let session = captures.stop(id) else { throw ArgusError.notFound("Capture") }
            return .capture(session)
        case .listCaptures:
            return .captures(captures.list())
        case .fetchCapture(let id):
            return .data(try captures.data(for: id))
        case .deleteCapture(let id):
            captures.delete(id)
            return .ok

        case .exportBackup:
            return .data(try StateStore.encoder.encode(state))
        case .importBackup(let data, let merge):
            let imported: FirewallState
            do { imported = try StateStore.decoder.decode(FirewallState.self, from: data) } catch {
                throw ArgusError.invalid("That file isn't an Argus backup.")
            }
            let newState = mutate { state in
                if merge {
                    let ruleIDs = Set(state.rules.map(\.id)), profileIDs = Set(state.profiles.map(\.id))
                    let groupURLs = Set(state.ruleGroups.compactMap(\.url))
                    state.rules += imported.rules.filter { !ruleIDs.contains($0.id) && !$0.isFromRuleGroup }
                    state.profiles += imported.profiles.filter { !profileIDs.contains($0.id) }
                    state.ruleGroups += imported.ruleGroups.filter { $0.url.map { !groupURLs.contains($0) } ?? true }
                } else {
                    let revision = state.revision
                    state = imported
                    state.revision = revision
                }
            }
            let missing = newState.ruleGroups.map(\.id).filter { id in inner.withLock { $0.blocklists[id] == nil } }
            if !missing.isEmpty { Task { await self.refreshRuleGroups(missing) } }
            return .state(newState)
        case .clearActivity:
            activity.clear()
            return .ok
        }
    }

    private func protectionChanged(_ enabled: Bool) {
        notice(.protectionChanged, title: enabled ? "Protection turned on" : "Protection turned off",
               detail: enabled ? "Argus is filtering connections again." : "All connections are allowed until protection is turned back on.")
    }
}
