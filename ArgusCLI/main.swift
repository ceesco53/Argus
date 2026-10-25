import ArgusKit
import Foundation

// argus — command line administration for the Argus firewall.
// Talks to the network filter when it's installed, otherwise to the monitor inside Argus.app.

let usage = """
usage: argus <command> [options]

  status                          Engine, mode, profile and today's totals
  mode [ask|allow|deny]           Show or set what happens to unknown connections
  protection on|off               Turn filtering on or off
  pause [1m|5m|30m|1h]            Allow everything for a while (no duration: until resumed)
  resume                          End a pause now

  blocked [--limit N]             Recently blocked connections and why
  allow HOST [--domain] [--process PATH|NAME]
                                  Always allow a host (or a whole domain), for every app or one

  rules [--json] [--process NAME] List rules
  rules add allow|deny [--process PATH|NAME] [--host H | --domain D | --ip ADDR/CIDR | --local-net]
            [--port PORTS] [--proto tcp|udp|icmp] [--incoming] [--priority]
            [--profile NAME] [--for 15m|2h|1d] [--note TEXT]
  rules delete|enable|disable ID...

  profiles                        List profiles
  profiles activate NAME|none
  profiles create NAME
  profiles delete NAME

  blocklists                      List subscribed blocklists and rule groups
  blocklists catalog              List community blocklists you can add
  blocklists add URL|CATALOG-ID [--name NAME]
  blocklists enable|disable|remove|update ID|NAME
  blocklists import FILE [--name NAME]

  apps [--json]                   Programs that used the network, with their code signatures
  connections [--limit N] [--json]  Busiest connections
  log [--follow] [--json]         Recent connection decisions
  traffic                         Live data rates per app

  capture start [--process PATH|NAME] [--host FILTER] [--seconds N]
  capture stop ID | capture list | capture save ID FILE

  backup FILE                     Write rules, profiles and settings to FILE
  restore FILE [--merge]          Replace (or merge) configuration from FILE
  lock | unlock                   Require administrator authentication for changes

IDs may be abbreviated to any unique prefix. Changes need root or an administrator
password while settings are locked.
"""

struct CLIError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

// MARK: - Arguments

struct Arguments {
    var positional: [String] = []
    var options: [String: String] = [:]
    var flags: Set<String> = []

    static let valueOptions: Set<String> = ["process", "host", "domain", "ip", "port", "proto", "profile", "for", "note", "name", "limit", "seconds"]

    init(_ raw: [String]) throws {
        var iterator = raw.makeIterator()
        while let arg = iterator.next() {
            if arg.hasPrefix("--") {
                let name = String(arg.dropFirst(2))
                if Arguments.valueOptions.contains(name) {
                    guard let value = iterator.next() else { throw CLIError("--\(name) needs a value") }
                    options[name] = value
                } else {
                    flags.insert(name)
                }
            } else {
                positional.append(arg)
            }
        }
    }

    func option(_ name: String) -> String? { options[name] }
    func has(_ flag: String) -> Bool { flags.contains(flag) }
}

// MARK: - Connecting

func withTimeout<T: Sendable>(_ seconds: Double, _ operation: @escaping @Sendable () async throws -> T) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask { try await operation() }
        group.addTask {
            try await Task.sleep(for: .seconds(seconds))
            throw CLIError("timed out")
        }
        defer { group.cancelAll() }
        return try await group.next()!
    }
}

/// Home directory of the invoking user, even under sudo.
func invokingHome() -> String {
    if getuid() == 0, let user = ProcessInfo.processInfo.environment["SUDO_USER"], let entry = getpwnam(user) {
        return String(cString: entry.pointee.pw_dir)
    }
    return NSHomeDirectory()
}

func connect() async throws -> (ArgusClient, ServerHello) {
    let hello = ClientHello(role: .commandLine, wantsAlerts: false)
    if let machName = Bundle.main.object(forInfoDictionaryKey: ArgusPaths.machServiceInfoKey) as? String, machName.contains(".") {
        let client = ArgusClient(channel: XPCChannel.connect(machServiceName: machName, serverRequirement: nil))
        client.start()
        if let server = try? await withTimeout(2, { try await client.hello(hello) }) { return (client, server) }
        client.close()
    }
    let path = ArgusPaths.monitorSocketPath(home: invokingHome())
    guard let channel = try? SocketChannel.connect(path: path) else {
        throw CLIError("Argus isn't running. Open Argus.app (or install its network filter) and try again.")
    }
    let client = ArgusClient(channel: channel)
    client.start()
    return (client, try await withTimeout(5) { try await client.hello(hello) })
}

/// Sends a request; if settings are locked, asks for an administrator and retries once.
@discardableResult
func send(_ client: ArgusClient, _ request: ArgusRequest) async throws -> ArgusResponse {
    do {
        return try await client.call(request)
    } catch ArgusError.locked where getuid() != 0 {
        client.authorization = try AdminAuthorization.obtain(prompt: "The argus command needs an administrator to change locked settings.")
        return try await client.call(request)
    }
}

func newState(_ client: ArgusClient, _ request: ArgusRequest) async throws -> FirewallState {
    guard case .state(let state) = try await send(client, request) else { throw CLIError("unexpected response") }
    return state
}

// MARK: - Output

func table(_ rows: [[String]], header: [String]) {
    let all = [header] + rows
    let widths = header.indices.map { column in all.map { $0[column].count }.max() ?? 0 }
    for (index, row) in all.enumerated() {
        let line = row.enumerated().map { column, cell in
            column == row.count - 1 ? cell : cell.padding(toLength: widths[column], withPad: " ", startingAt: 0)
        }.joined(separator: "  ")
        print(line)
        if index == 0 { print(widths.map { String(repeating: "─", count: $0) }.joined(separator: "  ")) }
    }
}

func printJSON<T: Encodable>(_ value: T) throws {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    encoder.dateEncodingStrategy = .iso8601
    print(String(decoding: try encoder.encode(value), as: UTF8.self))
}

func short(_ id: UUID) -> String { String(id.uuidString.prefix(8)).lowercased() }

let timeFormatter: DateFormatter = {
    let formatter = DateFormatter()
    formatter.dateFormat = "HH:mm:ss"
    return formatter
}()

func describe(_ entry: FlowLogEntry, state: FirewallState) -> String {
    let action = entry.verdict.action == .allow ? "ALLOW" : "DENY "
    let enforced = entry.verdict.isEnforced ? "" : " (not enforced)"
    let arrow = entry.direction == .incoming ? "←" : "→"
    return "\(timeFormatter.string(from: entry.date))  \(action)  \(entry.processName) \(arrow) \(entry.remote):\(entry.port)/\(entry.proto)  — \(entry.verdict.reason.explanation(in: state))\(enforced)"
}

// MARK: - Lookups

func resolve<T>(_ text: String, in items: [T], id: (T) -> UUID, name: (T) -> String, kind: String) throws -> T {
    let lower = text.lowercased()
    let byName = items.filter { name($0).lowercased() == lower }
    if byName.count == 1 { return byName[0] }
    let byID = items.filter { id($0).uuidString.lowercased().hasPrefix(lower) }
    guard byID.count == 1 else { throw CLIError(byID.isEmpty ? "No \(kind) matches “\(text)”." : "“\(text)” matches several \(kind)s; use more characters.") }
    return byID[0]
}

/// Accepts a full path, or the name of a program Argus has already seen.
func resolveProcess(_ text: String, client: ArgusClient) async throws -> String {
    if text.hasPrefix("/") { return text }
    let processes = try await client.activity(since: 0).processes
    let matches = processes.filter { $0.identity.name.lowercased() == text.lowercased() || ($0.identity.path as NSString).lastPathComponent == text }
    guard let match = matches.first else { throw CLIError("No program called “\(text)” has used the network yet. Pass its full path instead.") }
    if matches.count > 1 { throw CLIError("Several programs are called “\(text)”: \(matches.map(\.identity.path).joined(separator: ", "))") }
    return match.identity.path
}

func parseDuration(_ text: String) throws -> TimeInterval {
    guard let unit = text.last, let value = Double(text.dropLast()) else { throw CLIError("Durations look like 15m, 2h or 1d.") }
    switch unit {
    case "s": return value
    case "m": return value * 60
    case "h": return value * 3600
    case "d": return value * 86_400
    default: throw CLIError("Durations look like 15m, 2h or 1d.")
    }
}

// MARK: - Commands

func run(_ args: Arguments) async throws {
    guard let command = args.positional.first else {
        print(usage)
        return
    }
    if command == "help" || args.has("help") {
        print(usage)
        return
    }
    let rest = Array(args.positional.dropFirst())
    let (client, hello) = try await connect()
    defer { client.close() }

    switch command {
    case "status":
        let state = try await client.state()
        let activity = try await client.activity(since: 0)
        let engine = hello.host == .networkExtension ? "Network filter (enforcing)" : "Monitor in Argus.app (observing only — install the network filter to block)"
        let enabledGroups = state.ruleGroups.filter(\.isEnabled)
        print("Argus \(hello.version) — \(engine)")
        let paused = state.settings.isPaused() ? state.settings.pausedUntil : nil
        let pauseText = paused.map { $0.timeIntervalSinceNow > 86_400 * 365 ? " (paused until resumed)" : " (paused until \($0.formatted(date: .omitted, time: .shortened)))" } ?? ""
        print("Protection:  \(state.settings.protectionEnabled ? "On" : "OFF")\(pauseText)")
        print("Mode:        \(state.effectiveMode.displayName)\(state.activeProfile?.modeOverride != nil ? " (set by profile)" : "")")
        print("Profile:     \(state.activeProfile?.name ?? "None")")
        print("Rules:       \(state.rules.count) (\(state.rules.filter { $0.expiration.isTemporary }.count) temporary)")
        print("Blocklists:  \(enabledGroups.count) enabled, \(enabledGroups.reduce(0) { $0 + $1.entryCount }.formatted()) entries")
        print("Today:       \(activity.today.connections.formatted()) connections, \(activity.today.blocked.formatted()) blocked, ↓ \(Formatting.bytes(activity.today.bytesIn)) ↑ \(Formatting.bytes(activity.today.bytesOut))")
        print("Locked:      \(state.settings.lockEnabled ? "Yes" : "No")")
        if !activity.bpfUsers.isEmpty {
            print("Sniffing:    \(activity.bpfUsers.map { "\($0.name) (\($0.pid))" }.joined(separator: ", ")) reading /dev/bpf")
        }

    case "mode":
        guard let value = rest.first else {
            print(try await client.state().effectiveMode.displayName)
            return
        }
        let mode: FilterMode = switch value {
        case "ask", "alert": .alert
        case "allow", "silent-allow": .silentAllow
        case "deny", "silent-deny": .silentDeny
        default: throw CLIError("Modes are ask, allow and deny.")
        }
        _ = try await newState(client, .setMode(mode))
        print("Mode: \(mode.displayName)")

    case "protection":
        guard let value = rest.first, value == "on" || value == "off" else { throw CLIError("Use: argus protection on|off") }
        _ = try await newState(client, .setProtection(value == "on"))
        print("Protection \(value)")

    case "pause":
        let until = try rest.first.map { Date().addingTimeInterval(try parseDuration($0)) } ?? .distantFuture
        _ = try await newState(client, .pauseProtection(until: until))
        print(rest.isEmpty ? "Paused until you run `argus resume`. Everything is allowed." : "Paused until \(until.formatted(date: .omitted, time: .standard)). Everything is allowed.")

    case "resume":
        _ = try await newState(client, .pauseProtection(until: nil))
        print("Protection resumed.")

    case "blocked":
        let state = try await client.state()
        let log = try await client.activity(since: 0).log
        var seen = Set<String>()
        let blocked = log.reversed().filter { $0.verdict.action == .deny && seen.insert("\($0.processPath)|\($0.remote)").inserted }
        let limit = Int(args.option("limit") ?? "") ?? 25
        guard !blocked.isEmpty else {
            print("Nothing has been blocked recently.")
            return
        }
        table(blocked.prefix(limit).map { e in
            [timeFormatter.string(from: e.date), e.processName, "\(e.remote):\(e.port)", e.verdict.reason.explanation(in: state)]
        }, header: ["TIME", "PROGRAM", "DESTINATION", "WHY"])
        print("\nAllow one with: argus allow HOST [--process NAME]")

    case "allow":
        guard let target = rest.first?.lowercased() else { throw CLIError("Use: argus allow HOST [--domain] [--process PATH|NAME]") }
        var rule = Rule(action: .allow, origin: .commandLine)
        if IPNetwork(target) != nil {
            rule.remote = .address(target)
        } else {
            guard let name = DomainSet.normalize(target) else { throw CLIError("“\(target)” isn't a hostname or address.") }
            rule.remote = args.has("domain") ? .domain(DomainName.registrableDomain(of: name) ?? name) : .host(name)
        }
        if let process = args.option("process") { rule.process = .path(try await resolveProcess(process, client: client)) }
        rule.notes = "Allowed with argus allow"
        _ = try await newState(client, .saveRule(rule))
        print("Allowed: \(rule.summary)")

    case "rules":
        try await rules(rest, args, client)

    case "profiles":
        try await profiles(rest, client)

    case "blocklists", "groups":
        try await blocklists(rest, args, client)

    case "apps":
        let processes = try await client.activity(since: 0).processes.sorted { $0.totalBytes > $1.totalBytes }
        if args.has("json") { return try printJSON(processes) }
        table(processes.map { p in
            [p.identity.name, p.identity.signature.displayName, p.identity.teamIdentifier ?? "", "\(p.connectCount)", "\(p.denyCount)",
             Formatting.bytes(p.totalBytes), p.identity.path]
        }, header: ["PROGRAM", "SIGNATURE", "TEAM", "CONNECTIONS", "DENIED", "DATA", "PATH"])

    case "connections":
        let activity = try await client.activity(since: 0)
        let limit = Int(args.option("limit") ?? "") ?? 25
        let top = activity.connections.sorted { $0.totalBytes > $1.totalBytes }.prefix(limit)
        if args.has("json") { return try printJSON(Array(top)) }
        let names = Dictionary(activity.processes.map { ($0.id, $0.identity.name) }, uniquingKeysWith: { a, _ in a })
        table(top.map { c in
            [names[c.processPath] ?? c.processPath, c.remote, "\(c.port)/\(c.proto)", c.isBlocked ? "denied" : "allowed",
             "\(c.connectCount)", Formatting.bytes(c.bytesIn), Formatting.bytes(c.bytesOut)]
        }, header: ["PROGRAM", "SERVER", "PORT", "LAST", "COUNT", "IN", "OUT"])

    case "log":
        let state = try await client.state()
        var activity = try await client.activity(since: 0)
        if args.has("json") && !args.has("follow") { return try printJSON(activity.log) }
        activity.log.suffix(args.has("follow") ? 20 : 100).forEach { print(describe($0, state: state)) }
        guard args.has("follow") else { return }
        var revision = activity.revision
        while true {
            try await Task.sleep(for: .seconds(1))
            activity = try await client.activity(since: revision)
            revision = activity.revision
            for entry in activity.log {
                if args.has("json") { try printJSON(entry) } else { print(describe(entry, state: state)) }
            }
            fflush(stdout)
        }

    case "traffic":
        let activity = try await client.activity(since: 0)
        let names = Dictionary(activity.processes.map { ($0.id, $0.identity.name) }, uniquingKeysWith: { a, _ in a })
        let rows = activity.processRates.sorted { $0.value.total > $1.value.total }.map { path, rate in
            [names[path] ?? path, Formatting.rate(rate.bytesInPerSecond), Formatting.rate(rate.bytesOutPerSecond)]
        }
        print("Today: ↓ \(Formatting.bytes(activity.today.bytesIn))  ↑ \(Formatting.bytes(activity.today.bytesOut))\n")
        rows.isEmpty ? print("Nothing is moving data right now.") : table(rows, header: ["PROGRAM", "DOWN", "UP"])

    case "capture":
        try await capture(rest, args, client)

    case "backup":
        guard let file = rest.first else { throw CLIError("Use: argus backup FILE") }
        let data = try await client.data(.exportBackup)
        try data.write(to: URL(fileURLWithPath: file))
        print("Saved configuration to \(file)")

    case "restore":
        guard let file = rest.first else { throw CLIError("Use: argus restore FILE [--merge]") }
        let data = try Data(contentsOf: URL(fileURLWithPath: file))
        let state = try await newState(client, .importBackup(data, merge: args.has("merge")))
        print("Restored: \(state.rules.count) rules, \(state.profiles.count) profiles, \(state.ruleGroups.count) rule groups")

    case "lock", "unlock":
        var settings = try await client.state().settings
        settings.lockEnabled = command == "lock"
        _ = try await newState(client, .updateSettings(settings))
        print(command == "lock" ? "Settings locked. Changes now need an administrator." : "Settings unlocked.")

    default:
        throw CLIError("Unknown command “\(command)”. Run `argus help`.")
    }
}

func rules(_ rest: [String], _ args: Arguments, _ client: ArgusClient) async throws {
    let state = try await client.state()
    let sub = rest.first ?? "list"
    let allRules = state.rules + state.ruleGroups.filter(\.isEnabled).flatMap(\.rules)
    switch sub {
    case "list":
        var rules = allRules
        if let process = args.option("process") {
            let path = try await resolveProcess(process, client: client)
            rules = rules.filter { $0.process == .path(path) || $0.process == .any }
        }
        if args.has("json") { return try printJSON(rules) }
        table(rules.map { rule in
            [short(rule.id), rule.isEnabled ? "on" : "off", rule.action.rawValue + (rule.isPriority ? "!" : ""),
             rule.process.path.map { ProcessIdentity.defaultName(for: $0) } ?? "any", rule.remote.displayString,
             rule.ports == .any ? "any" : rule.ports.displayString, rule.proto.rawValue, rule.direction.rawValue,
             state.profile(id: rule.profileID)?.name ?? "all", rule.expiration == .never ? "" : rule.expiration.displayString,
             rule.isFromRuleGroup ? "group" : ""]
        }, header: ["ID", "ON", "ACTION", "PROCESS", "SERVER", "PORT", "PROTO", "DIR", "PROFILE", "EXPIRES", ""])

    case "add":
        guard rest.count >= 2, let action = RuleAction(rawValue: rest[1]) else { throw CLIError("Use: argus rules add allow|deny [options]") }
        var rule = Rule(action: action, origin: .commandLine)
        if let process = args.option("process"), process != "any" { rule.process = .path(try await resolveProcess(process, client: client)) }
        if let host = args.option("host") { rule.remote = .host(host.lowercased()) }
        if let domain = args.option("domain") { rule.remote = .domain(domain.lowercased()) }
        if let ip = args.option("ip") {
            guard IPNetwork(ip) != nil else { throw CLIError("“\(ip)” isn't an IP address or CIDR network.") }
            rule.remote = .address(ip)
        }
        if args.has("local-net") { rule.remote = .localNetwork }
        if let port = args.option("port") {
            guard let ports = PortMatch.parse(port) else { throw CLIError("Ports look like 443, 80,443 or 8000-8100.") }
            rule.ports = ports
        }
        if let proto = args.option("proto") {
            guard let value = ProtocolMatch(rawValue: proto.lowercased()) else { throw CLIError("Protocols are tcp, udp, icmp and any.") }
            rule.proto = value
        }
        if args.has("incoming") { rule.direction = .incoming }
        if args.has("both") { rule.direction = .both }
        rule.isPriority = args.has("priority")
        if let duration = args.option("for") { rule.expiration = .date(Date().addingTimeInterval(try parseDuration(duration))) }
        if let note = args.option("note") { rule.notes = note }
        if let profile = args.option("profile") {
            rule.profileID = try resolve(profile, in: state.profiles, id: \.id, name: \.name, kind: "profile").id
        }
        _ = try await newState(client, .saveRule(rule))
        print("Added \(short(rule.id)): \(rule.summary)")

    case "delete", "enable", "disable":
        let ids = try rest.dropFirst().map { text in
            try resolve(text, in: state.rules, id: \.id, name: { _ in "" }, kind: "rule").id
        }
        guard !ids.isEmpty else { throw CLIError("Give one or more rule IDs (see `argus rules`).") }
        let request: ArgusRequest = sub == "delete" ? .deleteRules(ids) : .setRulesEnabled(ids, sub == "enable")
        _ = try await newState(client, request)
        print("\(sub == "delete" ? "Deleted" : sub == "enable" ? "Enabled" : "Disabled") \(ids.count) rule\(ids.count == 1 ? "" : "s")")

    default:
        throw CLIError("Unknown rules command “\(sub)”.")
    }
}

func profiles(_ rest: [String], _ client: ArgusClient) async throws {
    let state = try await client.state()
    switch rest.first ?? "list" {
    case "list":
        let noProfile = ["", "No Profile", state.settings.activeProfileID == nil ? "●" : "", "", ""]
        table([noProfile] + state.profiles.map { profile in
            [short(profile.id), profile.name, profile.id == state.settings.activeProfileID ? "●" : "",
             profile.modeOverride?.displayName ?? "", profile.networks.map(\.displayName).joined(separator: ", ")]
        }, header: ["ID", "NAME", "ACTIVE", "MODE", "NETWORKS"])
    case "activate":
        guard rest.count >= 2 else { throw CLIError("Use: argus profiles activate NAME|none") }
        let target = rest[1] == "none" ? nil : try resolve(rest[1], in: state.profiles, id: \.id, name: \.name, kind: "profile")
        _ = try await newState(client, .activateProfile(target?.id))
        print("Active profile: \(target?.name ?? "None")")
    case "create":
        guard rest.count >= 2 else { throw CLIError("Use: argus profiles create NAME") }
        let profile = Profile(name: rest.dropFirst().joined(separator: " "))
        _ = try await newState(client, .saveProfile(profile))
        print("Created profile \(profile.name) (\(short(profile.id)))")
    case "delete":
        guard rest.count >= 2 else { throw CLIError("Use: argus profiles delete NAME") }
        let profile = try resolve(rest[1], in: state.profiles, id: \.id, name: \.name, kind: "profile")
        _ = try await newState(client, .deleteProfile(profile.id))
        print("Deleted profile \(profile.name) and its rules")
    default:
        throw CLIError("Unknown profiles command.")
    }
}

func blocklists(_ rest: [String], _ args: Arguments, _ client: ArgusClient) async throws {
    let state = try await client.state()
    let sub = rest.first ?? "list"
    func group(_ text: String) throws -> RuleGroup {
        try resolve(text, in: state.ruleGroups, id: \.id, name: \.name, kind: "blocklist")
    }
    switch sub {
    case "list":
        table(state.ruleGroups.map { g in
            [short(g.id), g.isEnabled ? "on" : "off", g.name, g.entryCount.formatted(),
             g.lastUpdated.map { $0.formatted(.relative(presentation: .named)) } ?? "never", g.lastError ?? ""]
        }, header: ["ID", "ON", "NAME", "ENTRIES", "UPDATED", "PROBLEM"])
    case "catalog":
        table(BlocklistCatalog.entries.map { e in
            [e.id, e.displayName, "~\(e.approximateEntries.formatted())", e.category.rawValue, e.isRecommended ? "recommended" : ""]
        }, header: ["ID", "NAME", "SIZE", "CATEGORY", ""])
    case "add":
        guard rest.count >= 2 else { throw CLIError("Use: argus blocklists add URL|CATALOG-ID") }
        var newGroup: RuleGroup
        if let entry = BlocklistCatalog.entry(id: rest[1]) {
            newGroup = RuleGroup(name: entry.displayName, summary: entry.summary, url: entry.url, catalogID: entry.id, format: entry.format)
        } else {
            guard let url = URL(string: rest[1]), url.scheme?.hasPrefix("http") == true else { throw CLIError("That isn't a URL or catalog ID (see `argus blocklists catalog`).") }
            newGroup = RuleGroup(name: args.option("name") ?? url.lastPathComponent, url: url)
        }
        if let name = args.option("name") { newGroup.name = name }
        _ = try await newState(client, .saveRuleGroup(newGroup))
        _ = try await newState(client, .refreshRuleGroups([newGroup.id]))
        let updated = try await client.state().ruleGroup(id: newGroup.id)
        if let error = updated?.lastError { throw CLIError("Added, but downloading failed: \(error)") }
        print("Added \(newGroup.name): \((updated?.entryCount ?? 0).formatted()) entries")
    case "enable", "disable":
        guard rest.count >= 2 else { throw CLIError("Use: argus blocklists \(sub) ID|NAME") }
        var target = try group(rest[1])
        target.isEnabled = sub == "enable"
        _ = try await newState(client, .saveRuleGroup(target))
        print("\(target.name) \(sub)d")
    case "remove":
        guard rest.count >= 2 else { throw CLIError("Use: argus blocklists remove ID|NAME") }
        let target = try group(rest[1])
        _ = try await newState(client, .deleteRuleGroup(target.id))
        print("Removed \(target.name)")
    case "update":
        let ids = try rest.count >= 2 ? [group(rest[1]).id] : state.ruleGroups.filter { $0.url != nil }.map(\.id)
        let updated = try await newState(client, .refreshRuleGroups(ids))
        for g in updated.ruleGroups where ids.contains(g.id) {
            print("\(g.name): \(g.lastError.map { "failed — \($0)" } ?? "\(g.entryCount.formatted()) entries")")
        }
    case "import":
        guard rest.count >= 2 else { throw CLIError("Use: argus blocklists import FILE [--name NAME]") }
        let url = URL(fileURLWithPath: rest[1])
        let data = try Data(contentsOf: url)
        _ = try await newState(client, .importRuleGroup(name: args.option("name") ?? url.deletingPathExtension().lastPathComponent, contents: data, format: .automatic))
        print("Imported \(url.lastPathComponent)")
    default:
        throw CLIError("Unknown blocklists command.")
    }
}

func capture(_ rest: [String], _ args: Arguments, _ client: ArgusClient) async throws {
    switch rest.first ?? "list" {
    case "start":
        var request = CaptureRequest()
        if let process = args.option("process") { request.processPath = try await resolveProcess(process, client: client) }
        request.remoteFilter = args.option("host")
        request.duration = args.option("seconds").flatMap(TimeInterval.init)
        let session = try await client.capture(.startCapture(request))
        print("Capturing \(session.processName ?? "all apps") as \(short(session.id)). Stop with `argus capture stop \(short(session.id))`.")
    case "stop":
        let sessions = try await client.captures()
        guard rest.count >= 2 else { throw CLIError("Use: argus capture stop ID") }
        let target = try resolve(rest[1], in: sessions, id: \.id, name: { _ in "" }, kind: "capture")
        let session = try await client.capture(.stopCapture(target.id))
        print("Stopped: \(session.packetCount.formatted()) packets, \(Formatting.bytes(UInt64(session.fileSize)))")
    case "list":
        table(try await client.captures().map { s in
            [short(s.id), s.processName ?? "All apps", s.startedAt.formatted(date: .abbreviated, time: .shortened),
             s.isActive ? "recording" : "done", s.packetCount.formatted(), Formatting.bytes(UInt64(s.fileSize))]
        }, header: ["ID", "PROGRAM", "STARTED", "STATE", "PACKETS", "SIZE"])
    case "save":
        guard rest.count >= 3 else { throw CLIError("Use: argus capture save ID FILE") }
        let target = try resolve(rest[1], in: try await client.captures(), id: \.id, name: { _ in "" }, kind: "capture")
        try await client.data(.fetchCapture(target.id)).write(to: URL(fileURLWithPath: rest[2]))
        print("Saved \(rest[2]) — open it with Wireshark or `tcpdump -r`.")
    default:
        throw CLIError("Unknown capture command.")
    }
}

// MARK: - Entry point

do {
    let args = try Arguments(Array(CommandLine.arguments.dropFirst()))
    try await run(args)
    exit(0)
} catch let error as ArgusError {
    FileHandle.standardError.write(Data("argus: \(error.errorDescription ?? "\(error)")\n".utf8))
    exit(1)
} catch {
    FileHandle.standardError.write(Data("argus: \(error)\n".utf8))
    exit(1)
}
