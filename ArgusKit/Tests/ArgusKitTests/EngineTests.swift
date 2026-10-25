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
