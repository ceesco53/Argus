import Foundation

/// Sparse time series of byte counts at one resolution.
struct TrafficSeries: Codable, Sendable {
    var resolution: Int64
    var retention: Int64
    var buckets: [Int64: TrafficBucket] = [:]

    init(resolution: Int64, retention: Int64) {
        self.resolution = resolution
        self.retention = retention
    }

    mutating func add(bytesIn: UInt64, bytesOut: UInt64, at time: Int64) {
        let start = time - time % resolution
        var bucket = buckets[start] ?? TrafficBucket(start: start, bytesIn: 0, bytesOut: 0)
        bucket.bytesIn += bytesIn
        bucket.bytesOut += bytesOut
        buckets[start] = bucket
    }

    /// Buckets from `since` to `now`, with empty buckets filled in so charts stay continuous.
    func points(since: Int64, now: Int64) -> [TrafficBucket] {
        let first = max(since, now - retention)
        var start = first - first % resolution
        var result: [TrafficBucket] = []
        while start <= now {
            result.append(buckets[start] ?? TrafficBucket(start: start, bytesIn: 0, bytesOut: 0))
            start += resolution
        }
        return result
    }

    func sum(from: Int64, to: Int64) -> (UInt64, UInt64) {
        var inBytes: UInt64 = 0, outBytes: UInt64 = 0
        var start = from - from % resolution
        while start <= to {
            if let b = buckets[start] { inBytes += b.bytesIn; outBytes += b.bytesOut }
            start += resolution
        }
        return (inBytes, outBytes)
    }

    mutating func prune(now: Int64) {
        let cutoff = now - retention
        if buckets.keys.contains(where: { $0 < cutoff }) { buckets = buckets.filter { $0.key >= cutoff } }
    }

    var isEmpty: Bool { buckets.isEmpty }
}

struct TrafficHistory: Codable, Sendable {
    var seconds = TrafficSeries(resolution: 1, retention: 180)
    var minutes = TrafficSeries(resolution: 60, retention: 86_400)
    var hours = TrafficSeries(resolution: 3600, retention: 86_400 * 30)

    mutating func add(bytesIn: UInt64, bytesOut: UInt64, at time: Int64) {
        guard bytesIn > 0 || bytesOut > 0 else { return }
        seconds.add(bytesIn: bytesIn, bytesOut: bytesOut, at: time)
        minutes.add(bytesIn: bytesIn, bytesOut: bytesOut, at: time)
        hours.add(bytesIn: bytesIn, bytesOut: bytesOut, at: time)
    }

    func series(_ resolution: TrafficResolution) -> TrafficSeries {
        switch resolution {
        case .second: seconds
        case .minute: minutes
        case .hour: hours
        }
    }

    /// Average over the last three complete seconds.
    func rate(now: Int64) -> Rate {
        let (i, o) = seconds.sum(from: now - 3, to: now - 1)
        return Rate(bytesInPerSecond: Double(i) / 3, bytesOutPerSecond: Double(o) / 3)
    }

    mutating func prune(now: Int64) {
        seconds.prune(now: now)
        minutes.prune(now: now)
        hours.prune(now: now)
    }

    var isEmpty: Bool { hours.isEmpty && minutes.isEmpty && seconds.isEmpty }
}

/// Aggregates connection decisions and traffic for the monitor, charts and log.
public final class ActivityTracker: @unchecked Sendable {
    struct OpenFlow: Sendable {
        var connectionKey: String
        var processPath: String
        var bytesIn: UInt64 = 0
        var bytesOut: UInt64 = 0
    }

    struct State: Codable, Sendable {
        var revision: UInt64 = 0
        /// Clients holding an older revision than this must take a full snapshot.
        var resetRevision: UInt64 = 0
        var processes: [String: ProcessRecord] = [:]
        var connections: [String: ConnectionRecord] = [:]
        var log: [FlowLogEntry] = []
        var events: [ActivityEvent] = []
        var today = DailyCounters(day: DailyCounters.dayKey(for: Date()))
        var global = TrafficHistory()
        var perProcess: [String: TrafficHistory] = [:]
        var bpfUsers: [BPFUser] = []
        var flows: [UUID: OpenFlow] = [:]

        enum CodingKeys: String, CodingKey {
            case revision, processes, connections, events, today, global, perProcess
        }

        init() {}

        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            // Everything a client cached before the restart is suspect (open flows were reset).
            revision = try c.decode(UInt64.self, forKey: .revision) + 1
            resetRevision = revision
            processes = try c.decode([String: ProcessRecord].self, forKey: .processes)
            connections = try c.decode([String: ConnectionRecord].self, forKey: .connections)
            events = try c.decode([ActivityEvent].self, forKey: .events)
            today = try c.decode(DailyCounters.self, forKey: .today)
            global = try c.decode(TrafficHistory.self, forKey: .global)
            perProcess = try c.decode([String: TrafficHistory].self, forKey: .perProcess)
            // Nothing is open after a restart.
            for key in processes.keys { processes[key]?.activeFlows = 0 }
            for key in connections.keys { connections[key]?.activeFlows = 0 }
        }

        mutating func nextRevision() -> UInt64 {
            revision += 1
            return revision
        }

        mutating func rollDay(_ now: Date) {
            let key = DailyCounters.dayKey(for: now)
            if today.day != key { today = DailyCounters(day: key) }
        }
    }

    static let logCapacity = 2000
    static let eventCapacity = 500
    static let connectionCapacity = 25_000
    static let retention: TimeInterval = 30 * 86_400

    private let state = Locked(State())

    public init() {}

    // MARK: Recording

    /// Records a decided connection. Pass `flowID` for allowed flows whose traffic will be reported.
    public func recordConnection(flowID: UUID?, context ctx: FlowContext, verdict: Verdict, now: Date = Date()) {
        state.withLock { s in
            s.rollDay(now)
            let revision = s.nextRevision()
            let key = ctx.connectionKey
            let allowed = verdict.action == .allow
            let tracksFlow = allowed && flowID != nil

            var connection = s.connections[key] ?? ConnectionRecord(
                id: key, processPath: ctx.process.path, remote: ctx.remoteDisplay, hostname: ctx.hostname,
                hostnameSource: ctx.hostnameSource, addresses: [], port: ctx.rulePort, proto: ctx.proto,
                direction: ctx.direction, firstSeen: now, lastSeen: now, connectCount: 0, allowCount: 0, denyCount: 0,
                bytesIn: 0, bytesOut: 0, activeFlows: 0, lastVerdict: verdict, revision: revision)
            connection.lastSeen = now
            connection.connectCount += 1
            if allowed { connection.allowCount += 1 } else { connection.denyCount += 1 }
            connection.lastVerdict = verdict
            if let address = ctx.address?.description, !connection.addresses.contains(address) {
                connection.addresses.insert(address, at: 0)
                if connection.addresses.count > 8 { connection.addresses.removeLast() }
            }
            if tracksFlow { connection.activeFlows += 1 }
            connection.revision = revision
            s.connections[key] = connection

            var process = s.processes[ctx.process.path] ?? ProcessRecord(
                identity: ctx.process, viaPaths: [], userIDs: [], firstSeen: now, lastSeen: now, connectCount: 0,
                allowCount: 0, denyCount: 0, unapprovedCount: 0, bytesIn: 0, bytesOut: 0, activeFlows: 0, revision: revision)
            process.identity = ctx.process
            process.lastSeen = now
            process.connectCount += 1
            if allowed { process.allowCount += 1 } else { process.denyCount += 1 }
            if verdict.reason.isUnapproved { process.unapprovedCount += 1 }
            if let via = ctx.via?.path, !process.viaPaths.contains(via) { process.viaPaths.append(via) }
            if !process.userIDs.contains(ctx.userID) { process.userIDs.append(ctx.userID) }
            if tracksFlow { process.activeFlows += 1 }
            process.revision = revision
            s.processes[ctx.process.path] = process

            s.today.connections += 1
            if !allowed {
                s.today.blocked += 1
                if case .blocklist = verdict.reason { s.today.blockedByLists += 1 }
            }
            s.log.append(FlowLogEntry(
                id: revision, date: now, processPath: ctx.process.path, processName: ctx.process.name, remote: ctx.remoteDisplay,
                address: ctx.address?.description, port: ctx.rulePort, proto: ctx.proto, direction: ctx.direction,
                userID: ctx.userID, verdict: verdict))
            if s.log.count > ActivityTracker.logCapacity { s.log.removeFirst(s.log.count - ActivityTracker.logCapacity) }

            if tracksFlow, let flowID {
                s.flows[flowID] = OpenFlow(connectionKey: key, processPath: ctx.process.path)
            }
        }
    }

    /// Reports cumulative byte counts for an open flow.
    public func updateFlow(_ id: UUID, totalIn: UInt64, totalOut: UInt64, closed: Bool, now: Date = Date()) {
        state.withLock { s in
            guard var flow = s.flows[id] else { return }
            let deltaIn = totalIn >= flow.bytesIn ? totalIn - flow.bytesIn : 0
            let deltaOut = totalOut >= flow.bytesOut ? totalOut - flow.bytesOut : 0
            flow.bytesIn = max(flow.bytesIn, totalIn)
            flow.bytesOut = max(flow.bytesOut, totalOut)
            if closed { s.flows[id] = nil } else { s.flows[id] = flow }
            guard deltaIn > 0 || deltaOut > 0 || closed else { return }

            s.rollDay(now)
            let revision = s.nextRevision()
            let time = Int64(now.timeIntervalSince1970)
            if var connection = s.connections[flow.connectionKey] {
                connection.bytesIn += deltaIn
                connection.bytesOut += deltaOut
                if closed { connection.activeFlows = max(0, connection.activeFlows - 1) }
                if deltaIn + deltaOut > 0 { connection.lastSeen = now }
                connection.revision = revision
                s.connections[flow.connectionKey] = connection
            }
            if var process = s.processes[flow.processPath] {
                process.bytesIn += deltaIn
                process.bytesOut += deltaOut
                if closed { process.activeFlows = max(0, process.activeFlows - 1) }
                process.revision = revision
                s.processes[flow.processPath] = process
            }
            s.today.bytesIn += deltaIn
            s.today.bytesOut += deltaOut
            s.global.add(bytesIn: deltaIn, bytesOut: deltaOut, at: time)
            s.perProcess[flow.processPath, default: TrafficHistory()].add(bytesIn: deltaIn, bytesOut: deltaOut, at: time)
        }
    }

    public var openFlowIDs: Set<UUID> { state.withLock { Set($0.flows.keys) } }

    @discardableResult
    public func addEvent(_ kind: ActivityEvent.Kind, title: String, detail: String = "", processPath: String? = nil, now: Date = Date()) -> ActivityEvent {
        state.withLock { s in
            let event = ActivityEvent(id: s.nextRevision(), date: now, kind: kind, title: title, detail: detail, processPath: processPath)
            s.events.append(event)
            if s.events.count > ActivityTracker.eventCapacity { s.events.removeFirst(s.events.count - ActivityTracker.eventCapacity) }
            return event
        }
    }

    /// Replaces the set of programs reading /dev/bpf and returns the newcomers.
    public func updateBPFUsers(_ users: [BPFUser]) -> [BPFUser] {
        state.withLock { s in
            let known = Dictionary(s.bpfUsers.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
            var merged: [BPFUser] = []
            var added: [BPFUser] = []
            for user in users {
                if let existing = known[user.id], existing.path == user.path { merged.append(existing) } else { merged.append(user); added.append(user) }
            }
            if merged != s.bpfUsers { _ = s.nextRevision() }
            s.bpfUsers = merged
            return added
        }
    }

    // MARK: Queries

    public func snapshot(since: UInt64, now: Date = Date()) -> ActivitySnapshot {
        state.withLock { s in
            s.rollDay(now)
            let full = since == 0 || since < s.resetRevision
            let time = Int64(now.timeIntervalSince1970)
            var rates: [String: Rate] = [:]
            for (path, history) in s.perProcess {
                let rate = history.rate(now: time)
                if rate.total > 0 { rates[path] = rate }
            }
            return ActivitySnapshot(
                revision: s.revision,
                isFull: full,
                processes: full ? Array(s.processes.values) : s.processes.values.filter { $0.revision > since },
                connections: full ? Array(s.connections.values) : s.connections.values.filter { $0.revision > since },
                log: full ? Array(s.log.suffix(500)) : Array(s.log.drop { $0.id <= since }.suffix(500)),
                events: full ? s.events : s.events.filter { $0.id > since },
                today: s.today,
                recentTraffic: s.global.seconds.points(since: time - 120, now: time - 1),
                processRates: rates,
                bpfUsers: s.bpfUsers)
        }
    }

    public func traffic(_ query: TrafficQuery, now: Date = Date()) -> [TrafficBucket] {
        state.withLock { s in
            let history = query.processPath.map { s.perProcess[$0] ?? TrafficHistory() } ?? s.global
            return history.series(query.resolution).points(since: Int64(query.since.timeIntervalSince1970), now: Int64(now.timeIntervalSince1970))
        }
    }

    public var revision: UInt64 { state.withLock { $0.revision } }

    public func process(_ path: String) -> ProcessRecord? { state.withLock { $0.processes[path] } }

    /// Earlier decisions about a domain, for the advisor. Only answers the user gave (rules and
    /// alert answers) count as this app's history; timeouts and silent modes don't.
    public func history(domain: String, processPath: String) -> DomainHistory {
        state.withLock { s in
            var history = DomainHistory()
            var others = Set<String>()
            for connection in s.connections.values {
                guard let host = connection.hostname, host == domain || host.hasSuffix("." + domain) else { continue }
                if connection.processPath == processPath {
                    switch connection.lastVerdict.reason {
                    case .rule, .alertAnswer:
                        if connection.lastVerdict.action == .allow { history.thisAppAllowed += connection.allowCount } else { history.thisAppDenied += connection.denyCount }
                    default:
                        break
                    }
                } else if connection.allowCount > 0 {
                    others.insert(s.processes[connection.processPath]?.identity.name ?? ProcessIdentity.defaultName(for: connection.processPath))
                }
            }
            history.otherAppsUsing = others.sorted()
            return history
        }
    }

    // MARK: Housekeeping

    public func tick(now: Date = Date()) {
        state.withLock { s in
            s.rollDay(now)
            let time = Int64(now.timeIntervalSince1970)
            s.global.prune(now: time)
            for path in s.perProcess.keys { s.perProcess[path]?.prune(now: time) }
            s.perProcess = s.perProcess.filter { !$0.value.isEmpty }

            let cutoff = now.addingTimeInterval(-ActivityTracker.retention)
            var removed = false
            if s.connections.values.contains(where: { $0.lastSeen < cutoff && $0.activeFlows == 0 }) {
                s.connections = s.connections.filter { $0.value.lastSeen >= cutoff || $0.value.activeFlows > 0 }
                removed = true
            }
            if s.connections.count > ActivityTracker.connectionCapacity {
                let keep = s.connections.values.sorted { $0.lastSeen > $1.lastSeen }.prefix(ActivityTracker.connectionCapacity * 9 / 10)
                s.connections = Dictionary(uniqueKeysWithValues: keep.map { ($0.id, $0) })
                removed = true
            }
            if removed {
                let livePaths = Set(s.connections.values.map(\.processPath))
                s.processes = s.processes.filter { livePaths.contains($0.key) || $0.value.activeFlows > 0 }
                // Deletions can't be expressed as a delta, so make every client resync.
                s.resetRevision = s.nextRevision()
            }
        }
    }

    public func clear() {
        state.withLock { s in
            let flows = s.flows
            let revision = s.revision + 1
            s = State()
            s.revision = revision
            s.resetRevision = revision
            s.flows = flows
        }
    }

    public func persistenceData() -> Data? {
        let copy = state.withLock { $0 }
        return try? JSONEncoder().encode(copy)
    }

    public func restore(from data: Data) {
        guard let restored = try? JSONDecoder().decode(State.self, from: data) else { return }
        state.withLock { s in
            let flows = s.flows
            s = restored
            s.flows = flows
            s.rollDay(Date())
        }
    }
}
