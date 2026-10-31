#if DEBUG
import ArgusKit
import Foundation

/// Made-up but realistic activity for screenshots and demos (`-ArgusDemo YES`, Debug builds only).
/// A private engine in a temporary folder: it never talks to the real filter, and nothing it does
/// reaches the real configuration, iCloud or the widgets. The same seed gives the same week.
final class DemoEngine: @unchecked Sendable {
    let core: FirewallCore
    let server: ArgusServer
    private let queue = DispatchQueue(label: "com.argus.demo")
    private var timer: DispatchSourceTimer?
    private var random = SplitMix(seed: 2026)
    private var carriers: [Carrier] = []
    /// Apps that first showed up this week, by name, and how many days ago.
    private let newThisWeek = ["News": 2.5, "Maps": 4.5]
    /// How much busier each app is right now than on average (a video playing in Safari), so the
    /// live chart has something to show while the monthly totals stay believable.
    private let liveBoost = ["Safari": 40.0, "Music": 6, "Google Chrome": 6, "Xcode": 5]
    private var firstSeen: [String: Date] = [:]

    /// The demo's own rules and blocklists, referred to by the verdicts it makes up.
    private enum ID {
        static let blocklist = UUID(uuidString: "D0000000-0000-0000-0000-000000000001")!
        static let hosts = UUID(uuidString: "D0000000-0000-0000-0000-000000000002")!
        static let firehol = UUID(uuidString: "D0000000-0000-0000-0000-000000000003")!
        static let safari = UUID(uuidString: "D0000000-0000-0000-0000-000000000010")!
        static let chrome = UUID(uuidString: "D0000000-0000-0000-0000-000000000011")!
        static let chromeAds = UUID(uuidString: "D0000000-0000-0000-0000-000000000012")!
        static let mail = UUID(uuidString: "D0000000-0000-0000-0000-000000000013")!
        static let music = UUID(uuidString: "D0000000-0000-0000-0000-000000000014")!
        static let xcode = UUID(uuidString: "D0000000-0000-0000-0000-000000000015")!
        static let messages = UUID(uuidString: "D0000000-0000-0000-0000-000000000016")!
        static let curl = UUID(uuidString: "D0000000-0000-0000-0000-000000000017")!
        static let syncAgent = UUID(uuidString: "D0000000-0000-0000-0000-000000000018")!
        static let scorecard = UUID(uuidString: "D0000000-0000-0000-0000-000000000019")!
        static let dns = UUID(uuidString: "D0000000-0000-0000-0000-00000000001A")!
        static let time = UUID(uuidString: "D0000000-0000-0000-0000-00000000001B")!
        static let home = UUID(uuidString: "D0000000-0000-0000-0000-000000000020")!
        static let office = UUID(uuidString: "D0000000-0000-0000-0000-000000000021")!
        static let cafe = UUID(uuidString: "D0000000-0000-0000-0000-000000000022")!
    }

    private struct Server {
        let host: String?
        let address: String
        var port: UInt16 = 443
        var proto: TransportProtocol = .tcp
    }

    private struct App {
        let identity: ProcessIdentity
        /// Share of connections.
        let weight: Double
        /// Average download while in use, bytes per second.
        let rate: Double
        let upload: Double
        let servers: [Server]
        let isBrowser: Bool
        let verdict: Verdict
    }

    /// A long-lived connection that carries an app's traffic history and live rate.
    private struct Carrier {
        let id: UUID
        let app: App
        var totalIn: UInt64 = 0
        var totalOut: UInt64 = 0
    }

    private let apps: [App]
    private let trackers = [
        Server(host: "securepubads.g.doubleclick.net", address: "142.250.72.98"),
        Server(host: "www.google-analytics.com", address: "142.250.72.78"),
        Server(host: "sb.scorecardresearch.com", address: "18.239.18.25"),
        Server(host: "ib.adnxs.com", address: "185.89.210.180"),
        Server(host: "connect.facebook.net", address: "157.240.22.19"),
        Server(host: "bat.bing.com", address: "13.107.21.200"),
    ]

    init() {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("ArgusDemo-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        apps = DemoEngine.makeApps()
        try? StateStore(directory: directory).saveState(DemoEngine.state(apps: apps))
        core = FirewallCore(host: .networkExtension, directory: directory)
        core.bpfScanner = nil
        server = ArgusServer(core: core)
    }

    func start() {
        seed(now: Date())
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 1, repeating: 1)
        timer.setEventHandler { [weak self] in self?.liveSecond() }
        timer.resume()
        self.timer = timer
    }

    func stop() {
        timer?.cancel()
        timer = nil
    }

    func makeClient() -> ArgusClient {
        let (clientEnd, serverEnd) = InMemoryChannel.pair()
        server.accept(serverEnd)
        return ArgusClient(channel: clientEnd)
    }

    // MARK: The cast

    private static func identity(_ path: String) -> ProcessIdentity {
        var identity = CodeSignature.identity(path: path)
        if identity.signature == .unknown { identity.signature = .apple }
        return identity
    }

    private static func makeApps() -> [App] {
        let apple = Verdict(.allow, .appleSoftware)
        var apps = [
            App(identity: identity("/Applications/Safari.app/Contents/MacOS/Safari"), weight: 0.30, rate: 9_000, upload: 0.08, servers: [
                Server(host: "www.youtube.com", address: "142.250.72.110", proto: .udp),
                Server(host: "www.apple.com", address: "17.253.144.10"),
                Server(host: "en.wikipedia.org", address: "185.15.58.224"),
                Server(host: "github.com", address: "140.82.112.3"),
                Server(host: "news.ycombinator.com", address: "209.216.230.207"),
                Server(host: "www.heise.de", address: "193.99.144.85"),
                Server(host: "www.bbc.co.uk", address: "212.58.244.22"),
                Server(host: "www.abc.net.au", address: "203.2.218.214"),
            ], isBrowser: true, verdict: Verdict(.allow, .rule(ID.safari))),
            App(identity: identity("/System/Applications/Music.app/Contents/MacOS/Music"), weight: 0.08, rate: 5_000, upload: 0.03, servers: [
                Server(host: "aod-ssl.itunes.apple.com", address: "17.253.21.202"),
                Server(host: "music.apple.com", address: "17.253.144.10"),
            ], isBrowser: false, verdict: Verdict(.allow, .rule(ID.music))),
            App(identity: identity("/System/Applications/Mail.app/Contents/MacOS/Mail"), weight: 0.08, rate: 500, upload: 0.4, servers: [
                Server(host: "imap.mail.me.com", address: "17.42.251.41", port: 993),
                Server(host: "smtp.mail.me.com", address: "17.42.251.57", port: 587),
            ], isBrowser: false, verdict: Verdict(.allow, .rule(ID.mail))),
            App(identity: identity("/System/Applications/News.app/Contents/MacOS/News"), weight: 0.04, rate: 1_500, upload: 0.05, servers: [
                Server(host: "news-edge.apple.com", address: "17.253.144.10"),
            ], isBrowser: false, verdict: Verdict(.allow, .learning)),
            App(identity: identity("/System/Applications/Maps.app/Contents/MacOS/Maps"), weight: 0.03, rate: 1_200, upload: 0.05, servers: [
                Server(host: "gspe19-ssl.ls.apple.com", address: "17.253.39.205"),
            ], isBrowser: false, verdict: Verdict(.allow, .learning)),
            App(identity: identity("/System/Applications/Messages.app/Contents/MacOS/Messages"), weight: 0.04, rate: 300, upload: 0.5, servers: [
                Server(host: "identity.ess.apple.com", address: "17.57.146.20"),
            ], isBrowser: false, verdict: Verdict(.allow, .rule(ID.messages))),
            App(identity: identity("/System/Applications/App Store.app/Contents/MacOS/App Store"), weight: 0.03, rate: 3_000, upload: 0.02, servers: [
                Server(host: "apps.apple.com", address: "17.253.144.10"),
            ], isBrowser: false, verdict: apple),
            App(identity: identity("/usr/libexec/apsd"), weight: 0.05, rate: 60, upload: 0.6, servers: [
                Server(host: "courier.push.apple.com", address: "17.57.146.52", port: 5223),
            ], isBrowser: false, verdict: apple),
            App(identity: identity("/usr/libexec/trustd"), weight: 0.05, rate: 80, upload: 0.3, servers: [
                Server(host: "ocsp2.apple.com", address: "17.253.37.205", port: 80),
            ], isBrowser: false, verdict: apple),
            App(identity: identity("/usr/libexec/nsurlsessiond"), weight: 0.04, rate: 2_000, upload: 0.02, servers: [
                Server(host: "mesu.apple.com", address: "17.253.21.205"),
            ], isBrowser: false, verdict: apple),
            App(identity: identity("/usr/sbin/mDNSResponder"), weight: 0.08, rate: 40, upload: 0.5, servers: [
                Server(host: "one.one.one.one", address: "1.1.1.1", port: 53, proto: .udp),
            ], isBrowser: false, verdict: Verdict(.allow, .rule(ID.dns))),
            App(identity: identity("/usr/libexec/timed"), weight: 0.01, rate: 2, upload: 0.5, servers: [
                Server(host: "time.apple.com", address: "17.253.4.125", port: 123, proto: .udp),
            ], isBrowser: false, verdict: Verdict(.allow, .rule(ID.time))),
            App(identity: identity("/usr/bin/curl"), weight: 0.01, rate: 120, upload: 0.1, servers: [
                Server(host: "api.github.com", address: "140.82.112.6"),
            ], isBrowser: false, verdict: Verdict(.allow, .rule(ID.curl))),
            App(identity: ProcessIdentity(path: "/usr/local/bin/sync-agent", name: "sync-agent", signature: .invalid),
                weight: 0.01, rate: 0, upload: 0, servers: [
                Server(host: "telemetry.sync-agent.example", address: "203.0.113.50"),
            ], isBrowser: false, verdict: Verdict(.deny, .rule(ID.syncAgent))),
        ]
        if FileManager.default.fileExists(atPath: "/Applications/Xcode.app") {
            apps.append(App(identity: identity("/Applications/Xcode.app/Contents/MacOS/Xcode"), weight: 0.03, rate: 3_000, upload: 0.03, servers: [
                Server(host: "developer.apple.com", address: "17.253.144.10"),
                Server(host: "devimages-cdn.apple.com", address: "17.253.21.200"),
            ], isBrowser: false, verdict: Verdict(.allow, .rule(ID.xcode))))
        }
        if FileManager.default.fileExists(atPath: "/Applications/Google Chrome.app") {
            apps.append(App(identity: identity("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"), weight: 0.14, rate: 4_000, upload: 0.1, servers: [
                Server(host: "docs.google.com", address: "142.250.72.110"),
                Server(host: "www.google.com", address: "142.250.72.100", proto: .udp),
                Server(host: "stackoverflow.com", address: "104.18.32.7"),
                Server(host: "www.reddit.com", address: "151.101.1.140"),
                Server(host: "www.rakuten.co.jp", address: "133.237.32.1"),
                Server(host: "speedtest.tele2.net", address: "90.130.70.73"),
            ], isBrowser: true, verdict: Verdict(.allow, .rule(ID.chrome))))
        }
        return apps
    }

    // MARK: Rules, blocklists and profiles

    private static func state(apps: [App]) -> FirewallState {
        var state = FirewallState()
        let now = Date()
        func path(_ name: String) -> ProcessMatch {
            .path(apps.first { $0.identity.name == name }?.identity.path ?? "/Applications/\(name).app/Contents/MacOS/\(name)")
        }
        func requirement(_ name: String) -> String? { apps.first { $0.identity.name == name }?.identity.designatedRequirement }

        state.profiles = [
            Profile(id: ID.home, name: "Home", symbolName: "house", networks: [NetworkIdentity(interface: .wifi, ssid: "Home", gatewayAddress: "192.168.1.1")]),
            Profile(id: ID.office, name: "Office", symbolName: "building.2", networks: [NetworkIdentity(interface: .ethernet, gatewayAddress: "10.0.0.1")]),
            Profile(id: ID.cafe, name: "Coffee Shop", symbolName: "cup.and.saucer", modeOverride: .alert,
                    notes: "Untrusted Wi-Fi: ask about everything, keep local devices out."),
        ]
        state.settings.activeProfileID = ID.home
        state.settings.mode = .alert

        var rules = [
            Rule(id: ID.dns, action: .allow, process: path("mDNSResponder"), remote: .any, proto: .any, direction: .both,
                 notes: "Resolves hostnames for every app. Blocking it breaks almost everything.", origin: .defaults),
            Rule(id: ID.time, action: .allow, process: path("timed"), remote: .any, ports: .single(123), proto: .udp,
                 notes: "Keeps the clock in sync.", origin: .defaults),
            Rule(action: .allow, remote: .any, ports: .ranges([PortRange(67, 68)]), proto: .udp, direction: .both,
                 notes: "DHCP: lets the Mac obtain an address on a network.", origin: .defaults),
            Rule(id: ID.safari, action: .allow, process: path("Safari"), codeRequirement: requirement("Safari"), remote: .any, origin: .alert),
            Rule(id: ID.mail, action: .allow, process: path("Mail"), codeRequirement: requirement("Mail"), remote: .host("imap.mail.me.com"), ports: .single(993), origin: .alert),
            Rule(action: .allow, process: path("Mail"), codeRequirement: requirement("Mail"), remote: .host("smtp.mail.me.com"), ports: .single(587), origin: .alert),
            Rule(id: ID.music, action: .allow, process: path("Music"), codeRequirement: requirement("Music"), remote: .domain("apple.com"), origin: .alert),
            Rule(id: ID.messages, action: .allow, process: path("Messages"), remote: .domain("apple.com"),
                 expiration: .date(now.addingTimeInterval(3600)), origin: .alert),
            Rule(id: ID.curl, action: .allow, process: path("curl"), remote: .host("api.github.com"), notes: "Allowed with argus allow", origin: .commandLine),
            Rule(id: ID.syncAgent, action: .deny, process: .path("/usr/local/bin/sync-agent"), remote: .any,
                 notes: "Unsigned helper I don't recognise.", origin: .user),
            Rule(id: ID.scorecard, action: .deny, remote: .domain("scorecardresearch.com"), isPriority: true,
                 notes: "Tracker. Priority, so no app rule can let it through.", origin: .user),
            Rule(action: .deny, remote: .localNetwork, profileID: ID.cafe, notes: "Keep strangers' devices away on café Wi-Fi.", origin: .user),
        ]
        if apps.contains(where: { $0.identity.name == "Xcode" }) {
            rules.append(Rule(id: ID.xcode, action: .allow, process: path("Xcode"), codeRequirement: requirement("Xcode"), remote: .domain("apple.com"), origin: .alert))
        }
        if apps.contains(where: { $0.identity.name == "Google Chrome" }) {
            rules.append(Rule(id: ID.chrome, action: .allow, process: path("Google Chrome"), codeRequirement: requirement("Google Chrome"), remote: .any, origin: .alert))
            rules.append(Rule(id: ID.chromeAds, action: .deny, process: path("Google Chrome"), remote: .domain("doubleclick.net"), origin: .user))
        }
        state.rules = rules

        func group(_ id: UUID, catalog: String, enabled: Bool, domains: Int, addresses: Int = 0) -> RuleGroup {
            let entry = BlocklistCatalog.entries.first { $0.id == catalog }
            var group = RuleGroup(id: id, name: entry?.name ?? catalog, summary: entry?.summary ?? "", url: entry?.url,
                                  catalogID: catalog, isEnabled: enabled, format: entry?.format ?? .automatic)
            group.lastUpdated = now.addingTimeInterval(-2 * 3600)
            group.lastAttempt = group.lastUpdated // not due, so nothing is downloaded
            group.domainCount = domains
            group.addressCount = addresses
            return group
        }
        state.ruleGroups = [
            group(ID.blocklist, catalog: "hagezi-light", enabled: true, domains: 98_412),
            group(ID.hosts, catalog: "stevenblack", enabled: true, domains: 79_215),
            group(ID.firehol, catalog: "firehol-level1", enabled: false, domains: 0, addresses: 4_510),
        ]
        return state
    }

    // MARK: A week of history

    private func dayCurve(_ date: Date) -> Double {
        let hour = Double(Calendar.current.component(.hour, from: date)) + Double(Calendar.current.component(.minute, from: date)) / 60
        let evening = exp(-pow(hour - 20.5, 2) / 6)
        let workday = exp(-pow(hour - 13, 2) / 12) * 0.8
        return 0.05 + workday + evening
    }

    private func context(_ app: App, _ server: Server) -> FlowContext {
        FlowContext(process: app.identity, pid: 400 + Int32(abs(app.identity.path.hashValue % 30_000)), userID: 501,
                    hostname: server.host, address: IPAddress(server.address), remotePort: server.port,
                    localAddress: IPAddress("192.168.1.24"), localPort: UInt16.random(in: 49_152...65_000), proto: server.proto)
    }

    /// One connection: which app, where, and what Argus decided.
    private func pickConnection(at time: Date = Date()) -> (App, Server, Verdict) {
        let present = apps.filter { firstSeen[$0.identity.name].map { $0 <= time } ?? true }
        var roll = Double.random(in: 0..<present.reduce(0) { $0 + $1.weight }, using: &random)
        let app = present.first { roll -= $0.weight; return roll < 0 } ?? present[0]
        if app.isBrowser, Double.random(in: 0..<1, using: &random) < 0.16 {
            let tracker = trackers.randomElement(using: &random)!
            let reason: VerdictReason = if tracker.host?.contains("scorecardresearch") == true {
                .rule(ID.scorecard)
            } else if app.identity.name == "Google Chrome", tracker.host?.contains("doubleclick") == true {
                .rule(ID.chromeAds)
            } else {
                .blocklist(Double.random(in: 0..<1, using: &random) < 0.7 ? ID.blocklist : ID.hosts)
            }
            return (app, tracker, Verdict(.deny, reason))
        }
        return (app, app.servers.randomElement(using: &random)!, app.verdict)
    }

    private func seed(now: Date) {
        let activity = core.activity
        let monthAgo = now.addingTimeInterval(-30 * 86_400)
        let weekAgo = now.addingTimeInterval(-7 * 86_400)
        let dayAgo = now.addingTimeInterval(-86_400)
        let liveStart = now.addingTimeInterval(-150)

        for (name, days) in newThisWeek { firstSeen[name] = now.addingTimeInterval(-days * 86_400) }
        var unborn = apps.filter { $0.rate > 0 && firstSeen[$0.identity.name] != nil }
        // Each app's busiest server carries its traffic.
        func addCarrier(_ app: App, at time: Date) {
            let id = UUID()
            activity.recordConnection(flowID: id, context: context(app, app.servers[0]), verdict: app.verdict, now: time)
            carriers.append(Carrier(id: id, app: app))
        }
        for app in apps where app.rate > 0 && firstSeen[app.identity.name] == nil { addCarrier(app, at: monthAgo) }

        var time = monthAgo
        var pending = 0.0
        while time < liveStart {
            let step: TimeInterval = time < dayAgo ? 3600 : 60
            let curve = dayCurve(time)
            for app in unborn where firstSeen[app.identity.name]! <= time { addCarrier(app, at: time) }
            unborn.removeAll { firstSeen[$0.identity.name]! <= time }
            if time >= weekAgo {
                pending += 1_200 * curve * step / 3600 * Double.random(in: 0.7...1.3, using: &random)
                while pending >= 1 {
                    record(pickConnection(at: time), at: time.addingTimeInterval(Double.random(in: 0..<step, using: &random)))
                    pending -= 1
                }
            }
            carry(seconds: step, at: time.addingTimeInterval(step / 2), curve: curve)
            time = time.addingTimeInterval(step)
        }
        while time < now {
            carry(seconds: 1, at: time, curve: dayCurve(time), live: true)
            time = time.addingTimeInterval(1)
        }

        func event(_ kind: ActivityEvent.Kind, _ title: String, _ detail: String, hoursAgo: Double, path: String? = nil) {
            _ = activity.addEvent(kind, title: title, detail: detail, processPath: path, now: now.addingTimeInterval(-hoursAgo * 3600))
        }
        event(.profileSwitched, "Switched to Home", "Joined the Home Wi-Fi network.", hoursAgo: 9)
        event(.ruleGroupUpdated, "Multi Light updated", "98,412 domains", hoursAgo: 2)
        event(.ruleGroupUpdated, "Unified Hosts updated", "79,215 domains", hoursAgo: 2)
        event(.invalidSignature, "sync-agent has an invalid code signature",
              "The program at /usr/local/bin/sync-agent was modified after it was signed. It may have been tampered with.",
              hoursAgo: 5, path: "/usr/local/bin/sync-agent")
    }

    /// One connection, with a short burst of traffic when it was allowed.
    private func record(_ connection: (App, Server, Verdict), at time: Date) {
        let (app, server, verdict) = connection
        guard verdict.action == .allow else {
            core.activity.recordConnection(flowID: nil, context: context(app, server), verdict: verdict, now: time)
            return
        }
        let id = UUID()
        core.activity.recordConnection(flowID: id, context: context(app, server), verdict: verdict, now: time)
        let size = exp(Double.random(in: app.isBrowser ? log(30_000)...log(2_000_000) : log(2_000)...log(200_000), using: &random))
        core.activity.updateFlow(id, totalIn: UInt64(size), totalOut: UInt64(size * app.upload), closed: true, now: time)
    }

    /// Adds `seconds` worth of traffic to every app's carrier.
    private func carry(seconds: Double, at time: Date, curve: Double, live: Bool = false) {
        for index in carriers.indices {
            let app = carriers[index].app
            let boost = live ? liveBoost[app.identity.name] ?? 3 : 1
            let burst = Double.random(in: 0..<1, using: &random) < 0.02 ? Double.random(in: 4...12, using: &random) : 1
            let incoming = app.rate * boost * curve * seconds * burst * Double.random(in: 0.4...1.6, using: &random)
            carriers[index].totalIn += UInt64(incoming)
            carriers[index].totalOut += UInt64(incoming * app.upload * Double.random(in: 0.6...1.4, using: &random))
            core.activity.updateFlow(carriers[index].id, totalIn: carriers[index].totalIn, totalOut: carriers[index].totalOut, closed: false, now: time)
        }
    }

    private func liveSecond() {
        let now = Date()
        carry(seconds: 1, at: now, curve: dayCurve(now), live: true)
        for _ in 0..<Int.random(in: 0...2, using: &random) { record(pickConnection(), at: now) }
    }
}

/// A small seeded random number generator, so every demo shows the same week.
struct SplitMix: RandomNumberGenerator {
    private var state: UInt64
    init(seed: UInt64) { state = seed }
    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}
#endif
