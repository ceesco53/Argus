import Foundation
import Testing
@testable import ArgusKit

let safari = ProcessIdentity(path: "/Applications/Safari.app/Contents/MacOS/Safari", name: "Safari", signature: .apple,
                             designatedRequirement: "identifier \"com.apple.Safari\" and anchor apple")
let curl = ProcessIdentity(path: "/usr/bin/curl", name: "curl", signature: .apple)
let unknownApp = ProcessIdentity(path: "/Applications/Tool.app/Contents/MacOS/Tool", name: "Tool", signature: .developerID,
                                 designatedRequirement: "identifier \"com.example.tool\"")

func flow(_ process: ProcessIdentity = unknownApp, host: String? = "api.example.com", address: String = "93.184.216.34",
          port: UInt16 = 443, proto: TransportProtocol = .tcp, direction: TrafficDirection = .outgoing, uid: UInt32 = 501) -> FlowContext {
    FlowContext(process: process, pid: 4242, processStartTime: 1, userID: uid, hostname: host, address: IPAddress(address),
                remotePort: port, localAddress: IPAddress("192.168.1.20"), localPort: 50000, proto: proto, direction: direction)
}

@Suite struct RuleEngineTests {
    @Test func moreSpecificRulesWin() {
        let rules = [
            Rule(action: .deny, remote: .any),
            Rule(action: .allow, process: .path(unknownApp.path), remote: .any),
            Rule(action: .deny, process: .path(unknownApp.path), remote: .domain("example.com")),
            Rule(action: .allow, process: .path(unknownApp.path), remote: .host("api.example.com")),
        ]
        let set = CompiledRuleSet(rules: rules, activeProfile: nil, blocklists: [])
        #expect(set.evaluate(flow())?.rule?.id == rules[3].id)
        #expect(set.evaluate(flow(host: "www.example.com"))?.rule?.id == rules[2].id)
        #expect(set.evaluate(flow(host: "other.org"))?.rule?.id == rules[1].id)
        #expect(set.evaluate(flow(curl))?.rule?.id == rules[0].id)
    }

    @Test func denyWinsTiesAndPriorityBeatsSpecificity() {
        let allow = Rule(action: .allow, process: .path(unknownApp.path), remote: .host("api.example.com"))
        let deny = Rule(action: .deny, process: .path(unknownApp.path), remote: .host("api.example.com"))
        #expect(CompiledRuleSet(rules: [allow, deny], activeProfile: nil, blocklists: []).evaluate(flow())?.action == .deny)

        let priorityAllow = Rule(action: .allow, remote: .any, isPriority: true)
        #expect(CompiledRuleSet(rules: [deny, priorityAllow], activeProfile: nil, blocklists: []).evaluate(flow())?.action == .allow)
    }

    @Test func portsProtocolsDirectionsAndUsers() {
        let rules = [
            Rule(action: .allow, remote: .any, ports: .single(443), proto: .tcp),
            Rule(action: .allow, remote: .any, ports: .ranges([PortRange(5000, 6000)]), direction: .incoming),
            Rule(action: .allow, remote: .any, userID: 502),
        ]
        let set = CompiledRuleSet(rules: rules, activeProfile: nil, blocklists: [])
        #expect(set.evaluate(flow())?.rule?.id == rules[0].id)
        #expect(set.evaluate(flow(proto: .udp)) == nil)
        #expect(set.evaluate(flow(port: 80)) == nil)
        // Incoming flows match on our local port (50000 here), so the range doesn't apply.
        #expect(set.evaluate(flow(port: 5500, direction: .incoming)) == nil)
        #expect(set.evaluate(flow(port: 80, uid: 502))?.rule?.id == rules[2].id)
    }

    @Test func addressAndLocalNetworkRules() {
        let rules = [
            Rule(action: .deny, remote: .address("93.184.0.0/16")),
            Rule(action: .allow, remote: .localNetwork),
        ]
        let set = CompiledRuleSet(rules: rules, activeProfile: nil, blocklists: [])
        #expect(set.evaluate(flow(host: nil))?.action == .deny)
        #expect(set.evaluate(flow(host: nil, address: "192.168.1.5"))?.action == .allow)
    }

    @Test func profilesScopeRules() {
        let home = UUID(), work = UUID()
        let rules = [Rule(action: .deny, remote: .any, profileID: work), Rule(action: .allow, remote: .any, profileID: home)]
        #expect(CompiledRuleSet(rules: rules, activeProfile: home, blocklists: []).evaluate(flow())?.action == .allow)
        #expect(CompiledRuleSet(rules: rules, activeProfile: work, blocklists: []).evaluate(flow())?.action == .deny)
        #expect(CompiledRuleSet(rules: rules, activeProfile: nil, blocklists: []).evaluate(flow()) == nil)
    }

    @Test func disabledAndExpiredRulesAreIgnored() {
        let rules = [
            Rule(action: .deny, remote: .any, isEnabled: false),
            Rule(action: .deny, remote: .any, expiration: .date(Date().addingTimeInterval(-5))),
        ]
        #expect(CompiledRuleSet(rules: rules, activeProfile: nil, blocklists: []).evaluate(flow()) == nil)
    }

    @Test func blocklistsYieldToProcessSpecificAllows() {
        let groupID = UUID()
        let list = CompiledBlocklist(domains: DomainSet(suffixes: ["example.com"]))
        let generic = CompiledRuleSet(rules: [Rule(action: .allow, remote: .any)], activeProfile: nil, blocklists: [(groupID, list)])
        let match = generic.evaluate(flow())
        #expect(match?.action == .deny)
        #expect(match?.blocklistID == groupID)

        let specific = CompiledRuleSet(rules: [Rule(action: .allow, process: .path(unknownApp.path), remote: .any)],
                                       activeProfile: nil, blocklists: [(groupID, list)])
        #expect(specific.evaluate(flow())?.action == .allow)
        // Blocklists only apply to outgoing connections.
        #expect(CompiledRuleSet(rules: [], activeProfile: nil, blocklists: [(groupID, list)]).evaluate(flow(direction: .incoming)) == nil)
    }

    @Test func portParsing() {
        #expect(PortMatch.parse("any") == .any)
        #expect(PortMatch.parse("443") == .single(443))
        #expect(PortMatch.parse("80, 443,8000-8100")?.contains(8050) == true)
        #expect(PortMatch.parse("9-1") == nil)
        #expect(PortMatch.parse("http") == nil)
    }

    @Test func registrableDomains() {
        #expect(DomainName.registrableDomain(of: "www.apple.com") == "apple.com")
        #expect(DomainName.registrableDomain(of: "news.bbc.co.uk") == "bbc.co.uk")
        #expect(DomainName.registrableDomain(of: "d1.cloudfront.net") == "d1.cloudfront.net")
        #expect(DomainName.registrableDomain(of: "1.2.3.4") == nil)
    }
}

@Suite struct PCAPTests {
    @Test func checksumMatchesRFC1071Example() {
        // Example from RFC 1071 §3: 0001 f203 f4f5 f6f7 sums to 0xddf2; checksum is its complement.
        #expect(PacketSynthesizer.checksum([0x00, 0x01, 0xF2, 0x03, 0xF4, 0xF5, 0xF6, 0xF7]) == ~UInt16(0xDDF2))
    }

    @Test func writesFilesTcpdumpCanRead() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("argus-test-\(UUID()).pcap")
        defer { try? FileManager.default.removeItem(at: url) }
        let writer = try PCAPWriter(url: url)
        var tcp = PacketSynthesizer(localAddress: IPAddress("192.168.1.20"), localPort: 50000, remoteAddress: IPAddress("93.184.216.34"),
                                    remotePort: 80, proto: .tcp, direction: .outgoing)
        for p in tcp.payload(Data("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".utf8), inbound: false) { try writer.write(p) }
        for p in tcp.payload(Data(repeating: 0x41, count: 20_000), inbound: true) { try writer.write(p) }
        for p in tcp.close() { try writer.write(p) }
        var udp = PacketSynthesizer(localAddress: IPAddress("fd00::2"), localPort: 5353, remoteAddress: IPAddress("2001:db8::53"),
                                    remotePort: 53, proto: .udp, direction: .outgoing)
        for p in udp.payload(Data([1, 2, 3, 4]), inbound: false) { try writer.write(p) }
        writer.close()

        // 3 handshake + 1 request + 3 response segments + 3 FIN + 1 UDP
        #expect(writer.packetCount == 11)

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/tcpdump")
        process.arguments = ["-nn", "-v", "-r", url.path]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = Pipe()
        try process.run()
        process.waitUntilExit()
        let output = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        #expect(process.terminationStatus == 0)
        #expect(output.contains("192.168.1.20.50000 > 93.184.216.34.80"))
        #expect(output.contains("Flags [S]"))
        #expect(output.contains("Flags [S.]"))
        #expect(output.contains("Flags [F.]"))
        #expect(output.contains("fd00::2.5353 > 2001:db8::53.53"))
        #expect(!output.contains("bad cksum"))
        #expect(!output.contains("incorrect"))
    }
}

@Suite struct ActivityTests {
    @Test func aggregatesConnectionsAndTraffic() {
        let tracker = ActivityTracker()
        let id = UUID()
        let now = Date()
        tracker.recordConnection(flowID: id, context: flow(), verdict: Verdict(.allow, .appleSoftware), now: now)
        tracker.recordConnection(flowID: nil, context: flow(), verdict: Verdict(.deny, .mode(.silentDeny)), now: now)
        tracker.updateFlow(id, totalIn: 1000, totalOut: 200, closed: false, now: now)
        tracker.updateFlow(id, totalIn: 1500, totalOut: 200, closed: true, now: now)

        let snapshot = tracker.snapshot(since: 0, now: now)
        #expect(snapshot.isFull)
        let connection = try! #require(snapshot.connections.first)
        #expect(connection.connectCount == 2)
        #expect(connection.allowCount == 1)
        #expect(connection.denyCount == 1)
        #expect(connection.bytesIn == 1500)
        #expect(connection.activeFlows == 0)
        #expect(snapshot.processes.first?.unapprovedCount == 1)
        #expect(snapshot.today.blocked == 1)
        #expect(snapshot.log.count == 2)

        let delta = tracker.snapshot(since: snapshot.revision, now: now)
        #expect(!delta.isFull)
        #expect(delta.connections.isEmpty)

        let minutes = tracker.traffic(TrafficQuery(resolution: .minute, since: now.addingTimeInterval(-120)), now: now)
        #expect(minutes.reduce(0) { $0 + $1.bytesIn } == 1500)
    }

    @Test func persistsAcrossRestarts() throws {
        let tracker = ActivityTracker()
        tracker.recordConnection(flowID: UUID(), context: flow(), verdict: Verdict(.allow, .appleSoftware))
        let data = try #require(tracker.persistenceData())
        let restored = ActivityTracker()
        restored.restore(from: data)
        let snapshot = restored.snapshot(since: 1)
        #expect(snapshot.isFull) // older client revisions must resync after a restore
        #expect(snapshot.connections.first?.activeFlows == 0)
    }

    @Test func silentFlowsStopCountingAsOpen() throws {
        let tracker = ActivityTracker()
        let id = UUID()
        let start = Date()
        func open() -> Int { tracker.snapshot(since: 0, now: start).connections.first?.activeFlows ?? -1 }
        tracker.recordConnection(flowID: id, context: flow(), verdict: Verdict(.allow, .appleSoftware), now: start)
        tracker.tick(now: start.addingTimeInterval(60))
        #expect(open() == 1)

        // No report of its end, and nothing else for a long while: no longer open.
        tracker.tick(now: start.addingTimeInterval(16 * 60))
        #expect(open() == 0)

        // It was alive after all: open again, and its bytes still count.
        tracker.updateFlow(id, totalIn: 500, totalOut: 0, closed: false, now: start.addingTimeInterval(17 * 60))
        #expect(open() == 1)
        #expect(tracker.snapshot(since: 0, now: start).connections.first?.bytesIn == 500)

        // Silent again, then its close arrives late: counted off once, not twice.
        tracker.tick(now: start.addingTimeInterval(40 * 60))
        tracker.updateFlow(id, totalIn: 500, totalOut: 0, closed: true, now: start.addingTimeInterval(41 * 60))
        #expect(open() == 0)
        #expect(tracker.snapshot(since: 0, now: start).processes.first?.activeFlows == 0)

        // A flow that never reports again is forgotten after a day.
        let lost = UUID()
        tracker.recordConnection(flowID: lost, context: flow(), verdict: Verdict(.allow, .appleSoftware), now: start)
        tracker.tick(now: start.addingTimeInterval(2 * 86_400))
        tracker.updateFlow(lost, totalIn: 9_999, totalOut: 0, closed: false, now: start.addingTimeInterval(2 * 86_400))
        #expect(open() == 0)
    }
}

@Suite struct BlocklistExceptionTests {
    @Test func ipListsNeverBlockTheLocalNetwork() {
        // FireHOL Level 1 lists the private ranges; a Mac's own DNS server lives in one.
        let list = CompiledBlocklist(addresses: IPRangeSet(networks: ["192.168.0.0/16", "10.0.0.0/8", "203.0.113.0/24"].compactMap(IPNetwork.init)))
        let set = CompiledRuleSet(rules: [], activeProfile: nil, blocklists: [(UUID(), list)])
        #expect(set.evaluate(flow(safari, host: "news.google.com", address: "192.168.50.53", port: 53, proto: .udp)) == nil)
        #expect(set.evaluate(flow(host: nil, address: "10.1.2.3")) == nil)
        #expect(set.evaluate(flow(host: nil, address: "203.0.113.5"))?.action == .deny) // internet addresses still match
    }

    @Test func anAllowRuleAsNarrowAsAListEntryWins() {
        let list = CompiledBlocklist(domains: DomainSet(exact: ["news.google.com"]))
        let allow = Rule(action: .allow, process: .any, remote: .host("news.google.com"))
        let set = CompiledRuleSet(rules: [allow], activeProfile: nil, blocklists: [(UUID(), list)])
        #expect(set.evaluate(flow(host: "news.google.com"))?.rule?.id == allow.id)
        // …while two rules at the same level still resolve to deny.
        let deny = Rule(action: .deny, process: .any, remote: .host("news.google.com"))
        #expect(CompiledRuleSet(rules: [allow, deny], activeProfile: nil, blocklists: []).evaluate(flow(host: "news.google.com"))?.action == .deny)
    }
}

@Suite struct PauseTests {
    @Test func pausingAllowsEverythingAndReleasesWaitingAlerts() async throws {
        let (core, delegate) = makeCore()
        _ = await core.handle(.saveRule(Rule(action: .deny, remote: .host("api.example.com"))), client: app, authorization: nil)
        let released = Locked<Verdict?>(nil)
        _ = core.decide(flowID: UUID(), context: flow(host: "other.example.com"), resume: { v in released.withLock { $0 = v } })
        #expect(delegate.alerts.current.count == 1)

        _ = await core.handle(.pauseProtection(until: Date().addingTimeInterval(300)), client: app, authorization: nil)
        #expect(released.current == Verdict(.allow, .paused)) // the waiting alert was let through
        #expect(core.pendingAlerts.isEmpty)
        #expect(core.decide(flowID: UUID(), context: flow(), resume: { _ in }) == .allow(Verdict(.allow, .paused)))

        _ = await core.handle(.pauseProtection(until: nil), client: app, authorization: nil)
        guard case .deny = core.decide(flowID: UUID(), context: flow(), resume: { _ in }) else {
            Issue.record("rules apply again after resuming")
            return
        }
    }

    @Test func anExpiredPauseNoLongerApplies() async {
        let (core, _) = makeCore()
        _ = await core.handle(.saveRule(Rule(action: .deny, remote: .any)), client: app, authorization: nil)
        var settings = core.state.settings
        settings.pausedUntil = Date().addingTimeInterval(-1)
        _ = await core.handle(.updateSettings(settings), client: app, authorization: nil)
        #expect(!core.state.settings.isPaused())
        guard case .deny = core.decide(flowID: UUID(), context: flow(), resume: { _ in }) else {
            Issue.record("expected the rule to apply")
            return
        }
    }
}

@Suite struct WebKitAttributionTests {
    static let webKit = ProcessIdentity(
        path: "/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking",
        name: "com.apple.WebKit.Networking", bundleIdentifier: "com.apple.WebKit.Networking", signature: .apple,
        designatedRequirement: "identifier \"com.apple.WebKit.Networking\" and anchor apple")
    static let safari = ProcessIdentity(path: "/Applications/Safari.app/Contents/MacOS/Safari", name: "Safari",
                                        bundleIdentifier: "com.apple.Safari", signature: .apple,
                                        designatedRequirement: "identifier \"com.apple.Safari\" and anchor apple")

    /// A WebKit connection made for Safari (pid 4242 works for pid 777).
    static func attributed(host: String = "grok.com") -> FlowContext {
        flow(webKit, host: host).attributingHelperTraffic(responsiblePID: { $0 == 4242 ? 777 : nil }, identity: { _ in safari })
    }

    @Test func webKitConnectionsAreFiledUnderTheirApp() {
        let context = WebKitAttributionTests.attributed()
        #expect(context.process.path == WebKitAttributionTests.safari.path)
        #expect(context.via?.path == WebKitAttributionTests.webKit.path)
        #expect(context.viaIsHelper)
        #expect(context.pid == 777)
        #expect(context.connectionKey.hasPrefix(WebKitAttributionTests.safari.path))

        // Other programs, and connections whose app is already known, are left alone.
        let other = flow().attributingHelperTraffic(responsiblePID: { _ in 777 }, identity: { _ in WebKitAttributionTests.safari })
        #expect(other.process.path == unknownApp.path && other.via == nil)
        let unknownOwner = flow(WebKitAttributionTests.webKit).attributingHelperTraffic(responsiblePID: { _ in nil })
        #expect(unknownOwner.process.path == WebKitAttributionTests.webKit.path)
    }

    @Test func appRulesAndEarlierHelperRulesBothApply() {
        let blockSafari = Rule(action: .deny, process: .path(WebKitAttributionTests.safari.path), remote: .any)
        #expect(CompiledRuleSet(rules: [blockSafari], activeProfile: nil, blocklists: [])
            .evaluate(WebKitAttributionTests.attributed())?.action == .deny) // "Block App" now covers its web traffic

        let helperRule = Rule(action: .allow, process: .path(WebKitAttributionTests.webKit.path), remote: .domain("grok.com"))
        let set = CompiledRuleSet(rules: [Rule(action: .deny, remote: .any), helperRule], activeProfile: nil, blocklists: [])
        #expect(set.evaluate(WebKitAttributionTests.attributed())?.rule?.id == helperRule.id)
        // The DNS resolver working for an app isn't a helper in this sense: its rules stay its own.
        var lookup = flow(WebKitAttributionTests.safari, host: "grok.com")
        lookup.via = WebKitAttributionTests.webKit
        #expect(set.evaluate(lookup)?.rule?.id != helperRule.id)
    }
}

@Suite struct HelperSignatureTests {
    @Test func helperRulesAreCheckedAgainstTheHelper() async {
        let (core, _) = makeCore()
        core.requirementChecker = { _, _ in .violated } // the app itself would fail any check
        var matching = Rule(action: .allow, process: .path(WebKitAttributionTests.webKit.path),
                            codeRequirement: WebKitAttributionTests.webKit.designatedRequirement)
        matching.remote = .domain("grok.com")
        _ = await core.handle(.saveRule(matching), client: app, authorization: nil)
        #expect(core.decide(flowID: UUID(), context: WebKitAttributionTests.attributed(), resume: { _ in })
            == .allow(Verdict(.allow, .rule(matching.id))))

        matching.codeRequirement = "identifier \"com.example.impostor\""
        _ = await core.handle(.saveRule(matching), client: app, authorization: nil)
        guard case .deny(let verdict) = core.decide(flowID: UUID(), context: WebKitAttributionTests.attributed(), resume: { _ in }) else {
            Issue.record("expected deny")
            return
        }
        #expect(verdict.reason == .signatureMismatch(matching.id))
    }
}

@Suite struct PrivateRelayTests {
    @Test func relayTunnelsAreRecognised() {
        let proxy = ProcessIdentity(path: "/usr/libexec/networkserviceproxy", signature: .apple)
        #expect(flow(proxy, host: nil, address: "17.248.1.1").isPrivateRelayTunnel)
        #expect(flow(curl, host: "mask.icloud.com").isPrivateRelayTunnel)
        #expect(flow(curl, host: "us-west.mask-h2.icloud.com").isPrivateRelayTunnel)
        #expect(!flow(curl, host: "grok.com").isPrivateRelayTunnel)
        #expect(!flow(curl, host: "notmask.icloud.com").isPrivateRelayTunnel)
    }

    @Test func unreportedFlowsDoNotStayOpen() async {
        let (core, _) = makeCore()
        _ = await core.handle(.setProtection(false), client: app, authorization: nil)
        let id = UUID()
        _ = core.decide(flowID: id, context: flow(), resume: { _ in })
        func open() -> Int { core.activity.snapshot(since: 0).connections.first?.activeFlows ?? -1 }
        #expect(open() == 1)
        core.flowWontBeReported(id)
        #expect(open() == 0)
    }
}

/// What drops off "Recently blocked" once it's been allowed.
@Suite struct RecentlyBlockedTests {
    let blockedAt = Date(timeIntervalSince1970: 1_800_000_000)

    func blocked(_ remote: String, process: ProcessIdentity = unknownApp, address: String? = nil,
                 action: RuleAction = .deny) -> FlowLogEntry {
        FlowLogEntry(id: 1, date: blockedAt, processPath: process.path, processName: process.name, remote: remote,
                     address: address ?? (IPAddress(remote) != nil ? remote : "93.184.216.34"), port: 443, proto: .tcp,
                     direction: .outgoing, userID: 501, verdict: Verdict(action, .alertTimeout))
    }

    func rules(_ rules: [Rule], groups: [RuleGroup] = []) -> CompiledRuleSet {
        var state = FirewallState()
        state.rules = rules
        state.ruleGroups = groups
        return CompiledRuleSet(rulesOf: state, now: blockedAt.addingTimeInterval(120))
    }

    var later: Date { blockedAt.addingTimeInterval(60) }

    @Test func anAllowMadeSinceDropsIt() {
        let entry = blocked("212.102.63.140")
        #expect(!rules([]).allowsSinceBlocked(entry))
        let forApp = Rule(action: .allow, process: .path(unknownApp.path), remote: .address("212.102.63.140"), createdAt: later)
        #expect(rules([forApp]).allowsSinceBlocked(entry))
        let forAll = Rule(action: .allow, remote: .host("ads.example.com"), createdAt: later)
        #expect(rules([forAll]).allowsSinceBlocked(blocked("ads.example.com")))
        let forDomain = Rule(action: .allow, process: .path(unknownApp.path), remote: .domain("example.com"), createdAt: later)
        #expect(rules([forDomain]).allowsSinceBlocked(blocked("ads.example.com")))
    }

    @Test func itStaysWhileItWouldStillBeBlocked() {
        let entry = blocked("ads.example.com")
        let older = Rule(action: .allow, process: .path(unknownApp.path), remote: .host("ads.example.com"),
                         createdAt: blockedAt.addingTimeInterval(-60))
        #expect(!rules([older]).allowsSinceBlocked(entry))
        var off = Rule(action: .allow, process: .path(unknownApp.path), remote: .host("ads.example.com"), createdAt: later)
        off.isEnabled = false
        #expect(!rules([off]).allowsSinceBlocked(entry))
        let allow = Rule(action: .allow, remote: .host("ads.example.com"), createdAt: later)
        let deny = Rule(action: .deny, process: .path(unknownApp.path), remote: .host("ads.example.com"), isPriority: true)
        #expect(!rules([allow, deny]).allowsSinceBlocked(entry))
        let otherApp = Rule(action: .allow, process: .path("/Applications/Other.app/Contents/MacOS/Other"),
                            remote: .host("ads.example.com"), createdAt: later)
        #expect(!rules([otherApp]).allowsSinceBlocked(entry))
        let expired = Rule(action: .allow, process: .path(unknownApp.path), remote: .host("ads.example.com"),
                           expiration: .date(blockedAt.addingTimeInterval(90)), createdAt: later)
        #expect(!rules([expired]).allowsSinceBlocked(entry))
        let allowed = Rule(action: .allow, process: .path(unknownApp.path), remote: .host("ads.example.com"), createdAt: later)
        #expect(!rules([allowed]).allowsSinceBlocked(blocked("ads.example.com", action: .allow)))
    }

    @Test func adDomainsAllowsCountOnlyInBrowsers() throws {
        var group = RuleGroup.adDomains()
        try group.apply([AdDomainDecision(.domain("example.com"), .allow)], now: later)
        let compiled = rules([], groups: [group])
        #expect(compiled.allowsSinceBlocked(blocked("ads.example.com", process: Chrome.app), process: Chrome.app))
        #expect(!compiled.allowsSinceBlocked(blocked("ads.example.com")))
    }
}

@Suite struct AlertScopeTests {
    func alert(_ host: String?, app: ProcessIdentity = unknownApp, address: String = "93.184.216.34") -> ConnectionAlert {
        ConnectionAlert(id: UUID(), createdAt: Date(), deadline: nil, process: app, via: nil, pid: 4242, userID: 501,
                        hostname: host, address: address, port: 443, proto: .tcp, direction: .outgoing,
                        pendingConnections: 1, signatureWarning: nil)
    }

    func rule(_ remote: RemoteMatch, app: ProcessIdentity = unknownApp, _ action: RuleAction = .allow) -> Rule {
        Rule(action: action, process: .path(app.path), remote: remote, ports: .single(443))
    }

    @Test func aSiteAnsweredBeforeStartsOnTheWholeDomain() {
        let style = alert("style.schwab.com")
        #expect(!style.prefersDomain("schwab.com", rules: [], waiting: [style]))
        #expect(style.prefersDomain("schwab.com", rules: [rule(.host("www.schwab.com"))], waiting: []))
        #expect(style.prefersDomain("schwab.com", rules: [rule(.domain("schwab.com"), .deny)], waiting: []))
        // Another app's rule, another site, or a rule for this very server don't count.
        #expect(!style.prefersDomain("schwab.com", rules: [rule(.host("www.schwab.com"), app: safari)], waiting: []))
        #expect(!style.prefersDomain("schwab.com", rules: [rule(.host("www.notschwab.com"))], waiting: []))
        #expect(!style.prefersDomain("schwab.com", rules: [rule(.host("style.schwab.com"))], waiting: []))
        var disabled = rule(.host("www.schwab.com"))
        disabled.isEnabled = false
        #expect(!style.prefersDomain("schwab.com", rules: [disabled], waiting: []))
    }

    @Test func moreAlertsWaitingFromTheSiteStartOnTheWholeDomain() {
        let style = alert("style.schwab.com")
        #expect(style.prefersDomain("schwab.com", rules: [], waiting: [style, alert("client.schwab.com")]))
        #expect(!style.prefersDomain("schwab.com", rules: [], waiting: [style, alert("client.schwab.com", app: safari)]))
        #expect(!style.prefersDomain("schwab.com", rules: [], waiting: [style, alert(nil)]))
    }

    @Test func countsHowAnAppWasAnsweredBefore() {
        let game = alert(nil, address: "155.133.238.194")
        let rules = (0..<6).map { rule(.address("162.254.197.\($0)")) } + [rule(.host("larian.com"), app: safari, .deny)]
        #expect(game.answeredBefore(in: rules) == (allowed: 6, denied: 0))
        #expect(game.answeredBefore(in: rules + [rule(.host("ads.example.com"), .deny)]) == (allowed: 6, denied: 1))
    }

    @Test func rulesForBothTransportsShowJustThePort() {
        #expect(Formatting.port(443, proto: .udp) == "port 443 (HTTPS)")
        #expect(Formatting.port(53, proto: .tcp) == "port 53 (DNS)")
        #expect(Formatting.port(27045, proto: .udp) == "port 27045")
    }
}

/// The wider answer an alert starts on: what it shares with the app's other alerts and rules.
@Suite struct AlertPatternTests {
    let game = ProcessIdentity(path: "/Applications/Game.app/Contents/MacOS/game", name: "game", signature: .developerID,
                               designatedRequirement: "identifier \"com.example.game\"")

    func relay(_ address: String, _ port: UInt16, host: String? = nil, app: ProcessIdentity? = nil,
               direction: TrafficDirection = .outgoing) -> ConnectionAlert {
        ConnectionAlert(id: UUID(), createdAt: Date(), deadline: nil, process: app ?? game, via: nil, pid: 4242, userID: 501,
                        hostname: host, address: address, port: port, proto: .udp, direction: direction,
                        pendingConnections: 1, signatureWarning: nil)
    }

    func allowed(_ remote: RemoteMatch, _ ports: PortMatch, _ action: RuleAction = .allow, app: ProcessIdentity? = nil) -> Rule {
        Rule(action: action, process: .path((app ?? game).path), remote: remote, ports: ports, origin: .alert)
    }

    let hundred = PortRange(27000, 27099)

    @Test func relaysOnSeveralNetworksStartOnAnyServerAndTheirPorts() {
        let alert = relay("155.133.252.87", 27024)
        let others = [relay("162.254.193.98", 27031), relay("103.10.124.118", 27018), relay("146.66.155.4", 27040)]
        #expect(alert.pattern(rules: [], waiting: [alert] + others) == AlertPattern(servers: .any, ports: hundred))
        // Earlier answers count like waiting alerts.
        let rules = [allowed(.address("162.254.193.98"), .single(27031)), allowed(.host("103.10.124.118"), .single(27018)),
                     allowed(.address("146.66.155.4"), .single(27040))]
        #expect(alert.pattern(rules: rules, waiting: [alert]) == AlertPattern(servers: .any, ports: hundred))
        // Two other networks aren't enough for any server; the ports are still a stretch.
        #expect(alert.pattern(rules: [], waiting: Array(others.prefix(2))) == AlertPattern(ports: hundred))
        // Nor are another app's, or anything for an app that was denied something.
        let safariRules = rules.map { allowed($0.remote, $0.ports, app: safari) }
        #expect(alert.pattern(rules: safariRules, waiting: others.map { relay($0.address!, $0.port, app: safari) }) == nil)
        #expect(alert.pattern(rules: rules + [allowed(.host("telemetry.example.com"), .any, .deny)], waiting: [])
            == AlertPattern(ports: hundred))
        var off = rules
        off[0].isEnabled = false
        #expect(alert.pattern(rules: off, waiting: []) == AlertPattern(ports: hundred)) // a rule switched off wasn't an answer
    }

    @Test func neighboursStartOnTheNetworkTheyShare() {
        let alert = relay("155.133.252.87", 27024)
        let near = IPNetwork("155.133.252.0/24")!, wide = IPNetwork("155.133.0.0/16")!
        #expect(alert.networks == [near, wide])
        #expect(alert.pattern(rules: [], waiting: [relay("155.133.252.9", 27024)]) == AlertPattern(servers: .network(near)))
        #expect(alert.pattern(rules: [allowed(.address("155.133.252.9"), .single(27024), .deny)], waiting: [])
            == AlertPattern(servers: .network(near)))
        // Further apart, but in the same wider network.
        #expect(alert.pattern(rules: [], waiting: [relay("155.133.252.9", 27024), relay("155.133.238.194", 27024)])
            == AlertPattern(servers: .network(wide)))
        // A server on another port has nothing to do with this one, and this address itself isn't a neighbour.
        #expect(alert.pattern(rules: [], waiting: [relay("155.133.252.9", 443), relay("155.133.252.87", 9000)]) == nil)
        // IPv6 has its own networks.
        let v6 = relay("2a01:bc80:8:100::1f", 27024)
        #expect(v6.networks.map(\.description) == ["2a01:bc80:8:100::/64", "2a01:bc80:8::/48"])
        #expect(v6.pattern(rules: [], waiting: [relay("2a01:bc80:8:100::20", 27024)])?.servers == .network(v6.networks[0]))
    }

    @Test func serversWithNamesAndTheLocalNetworkKeepTheirOwnChoices() {
        let others = [relay("162.254.193.98", 443), relay("103.10.124.118", 443), relay("146.66.155.4", 443), relay("93.184.216.34", 443)]
        #expect(relay("155.133.252.87", 443).pattern(rules: [], waiting: others)?.servers == .any)
        // A name tells this server from the others, and its domain is what widens it.
        let named = relay("155.133.252.87", 443, host: "api.example.com")
        #expect(named.networks.isEmpty)
        #expect(named.pattern(rules: [], waiting: others) == nil)
        // Named servers don't make a nameless one part of a crowd either.
        let sites = ["a.example.com", "b.example.org", "c.example.net", "d.example.io"].map { relay("93.184.216.34", 443, host: $0) }
        #expect(relay("155.133.252.87", 443).pattern(rules: [], waiting: sites) == nil)
        let local = relay("192.168.1.40", 27024)
        #expect(local.networks.isEmpty)
        #expect(local.pattern(rules: [], waiting: [relay("192.168.1.41", 27024)]) == nil)
        // Connections coming in are a different question.
        let incoming = relay("155.133.252.87", 27024, direction: .incoming)
        #expect(incoming.pattern(rules: [], waiting: [relay("155.133.252.9", 27024, direction: .incoming)]) == nil)
    }

    @Test func aStretchOfPortsNeedsThreeNeighbours() {
        func stretch(_ port: UInt16, _ others: [UInt16]) -> PortRange? { AlertPattern.stretch(around: port, in: others.map { $0...$0 }) }
        #expect(stretch(27024, [27031, 27018]) == hundred)
        #expect(stretch(27024, [27031]) == nil)
        #expect(stretch(27024, [27024, 27024]) == nil) // the same port again
        #expect(stretch(27095, [27110, 27180]) == PortRange(27000, 27199))
        #expect(stretch(1050, [1030, 1090]) == PortRange(1024, 1099))
        #expect(stretch(65500, [65510, 65530]) == PortRange(65500, 65535))
        // Well-known ports are services of their own, and ports far apart aren't neighbours.
        #expect(stretch(110, [80, 143]) == nil)
        #expect(stretch(8080, [8443, 9000]) == nil)
        // Ports all over the place are an app picking them at random.
        #expect(stretch(50000, stride(from: UInt16(50090), through: 52000, by: 90).map { $0 }) == nil)
        // A named server on a stretch of ports widens its ports only.
        let named = relay("93.184.216.34", 5001, host: "relay.example.com")
        let more = [relay("93.184.216.34", 5002, host: "relay.example.com"), relay("93.184.216.34", 5003, host: "relay.example.com")]
        #expect(named.pattern(rules: [], waiting: more) == AlertPattern(ports: PortRange(5000, 5099)))
    }

    @Test func aWiderRuleOnTheNextPortsIsCarriedOn() {
        // Already allowed anywhere on 27000–27099; the next relay is just past the end.
        let alert = relay("155.133.252.87", 27105)
        #expect(alert.pattern(rules: [allowed(.any, .ranges([hundred]))], waiting: [])
            == AlertPattern(servers: .any, ports: PortRange(27000, 27199)))
        let network = IPNetwork("155.133.0.0/16")!
        #expect(alert.pattern(rules: [allowed(.address(network.description), .ranges([hundred]))], waiting: [])
            == AlertPattern(servers: .network(network), ports: PortRange(27000, 27199)))
        // Networks answered before count towards any server like single servers do.
        let networks = ["162.254.192.0/21", "103.10.124.0/23", "146.66.152.0/21"].map { allowed(.address($0), .ranges([hundred])) }
        #expect(alert.pattern(rules: networks, waiting: [])?.servers == .any)
    }

    @Test func answersMakeRulesForNetworksAndStretchesOfPorts() {
        func rule(_ decision: AlertDecision, host: String? = nil, address: String = "155.133.252.87") -> Rule {
            decision.rule(process: game, hostname: host, address: IPAddress(address), port: 27024, direction: .outgoing, userID: 501, activeProfile: nil)
        }
        let wide = rule(AlertDecision(action: .allow, remoteScope: .address, networkPrefix: 24, portRange: hundred))
        #expect(wide.remote == .address("155.133.252.0/24"))
        #expect(wide.ports == .ranges([hundred]))
        #expect(wide.summary == "Allow game → 155.133.252.0/24 port 27000-27099")
        #expect(rule(AlertDecision(action: .allow, remoteScope: .any, portRange: hundred)).remote == .any)
        #expect(rule(AlertDecision(action: .allow, remoteScope: .address, networkPrefix: 48), address: "2a01:bc80:8:100::1f").remote == .address("2a01:bc80:8::/48"))
        // Nonsense falls back to the one address and port rather than something wider.
        #expect(rule(AlertDecision(action: .allow, remoteScope: .address, networkPrefix: 0)).remote == .address("155.133.252.87"))
        #expect(rule(AlertDecision(action: .allow, remoteScope: .address, networkPrefix: 64)).remote == .address("155.133.252.87"))
        #expect(rule(AlertDecision(action: .allow, portRange: PortRange(5000, 5099))).ports == .single(27024))
        #expect(rule(AlertDecision(action: .allow, portScope: .anyPort, portRange: hundred)).ports == .any)
        // A network is for a server without a name.
        #expect(rule(AlertDecision(action: .allow, remoteScope: .host, networkPrefix: 24), host: "api.example.com").remote == .host("api.example.com"))
        #expect(IPNetwork("155.133.0.0/16")?.familiarDescription == "155.133.x.x")
        #expect(IPNetwork("155.133.252.0/23")?.familiarDescription == "155.133.252.0/23")
    }

    @Test func olderEnginesStillReadAnAnswer() throws {
        // The additions are left out of a plain answer and ignored where they're unknown, so an
        // engine from before them makes the rule for the one address and port.
        let plain = try JSONEncoder().encode(AlertDecision(action: .allow))
        #expect(!String(decoding: plain, as: UTF8.self).contains("networkPrefix"))
        #expect(!String(decoding: plain, as: UTF8.self).contains("portRange"))
        #expect(try JSONDecoder().decode(AlertDecision.self, from: plain) == AlertDecision(action: .allow))
        let wide = AlertDecision(action: .allow, remoteScope: .address, networkPrefix: 16, portRange: hundred)
        #expect(try JSONDecoder().decode(AlertDecision.self, from: JSONEncoder().encode(wide)) == wide)
    }
}
