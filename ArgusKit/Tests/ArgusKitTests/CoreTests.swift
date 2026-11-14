import Foundation
import Testing
@testable import ArgusKit

/// Records what the core asks of its host.
final class TestDelegate: FirewallCoreDelegate, @unchecked Sendable {
    let alerts = Locked<[ConnectionAlert]>([])
    let events = Locked<[ArgusEvent]>([])
    var acceptsAlerts = true

    func firewallCore(_ core: FirewallCore, present alert: ConnectionAlert) -> Bool {
        guard acceptsAlerts else { return false }
        alerts.withLock { $0.append(alert) }
        return true
    }

    func firewallCore(_ core: FirewallCore, broadcast event: ArgusEvent) {
        events.withLock { $0.append(event) }
    }
}

func makeCore(host: EngineHost = .networkExtension) -> (FirewallCore, TestDelegate) {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("argus-core-\(UUID())")
    let core = FirewallCore(host: host, directory: directory)
    core.bpfScanner = nil
    core.requirementChecker = { _, _ in .satisfied }
    let delegate = TestDelegate()
    core.delegate = delegate
    return (core, delegate)
}

let app = ClientContext(userID: 501, pid: 1, role: .app)

@Suite struct CoreTests {
    @Test func defaultsAllowAppleAndLocalButAskForOthers() {
        let (core, delegate) = makeCore()
        #expect(core.decide(flowID: UUID(), context: flow(safari), resume: { _ in }) == .allow(Verdict(.allow, .appleSoftware)))
        #expect(core.decide(flowID: UUID(), context: flow(address: "192.168.1.1"), resume: { _ in }) == .allow(Verdict(.allow, .localNetwork)))
        guard case .pause = core.decide(flowID: UUID(), context: flow(), resume: { _ in }) else {
            Issue.record("expected an alert")
            return
        }
        #expect(delegate.alerts.current.count == 1)
    }

    @Test func alertAnswersCreateRulesAndReleaseFoldedConnections() async {
        let (core, delegate) = makeCore()
        let released = Locked<[Verdict]>([])
        for _ in 0..<3 {
            _ = core.decide(flowID: UUID(), context: flow(), resume: { v in released.withLock { $0.append(v) } })
        }
        let alerts = delegate.alerts.current
        #expect(alerts.count == 1) // repeats join the first alert
        let alert = try! #require(alerts.first)

        // A second app's alert to a different host stays pending...
        _ = core.decide(flowID: UUID(), context: flow(host: "other.example.com"), resume: { _ in })
        #expect(core.pendingAlerts.count == 2)

        // ...until a domain-wide rule covers it too.
        let response = await core.handle(.resolveAlert(alert.id, AlertDecision(action: .allow, remoteScope: .domain("example.com"), portScope: .anyPort)),
                                         client: app, authorization: nil)
        guard case .ok = response else { Issue.record("unexpected \(response)"); return }
        #expect(released.current.count == 3)
        #expect(released.current.allSatisfy { $0.action == .allow })
        #expect(core.pendingAlerts.isEmpty)

        let rule = try! #require(core.state.rules.last)
        #expect(rule.process == .path(unknownApp.path))
        #expect(rule.remote == .domain("example.com"))
        #expect(rule.codeRequirement == unknownApp.designatedRequirement)
        #expect(rule.origin == .alert)

        // The next connection is decided by the rule without asking.
        guard case .allow(let verdict) = core.decide(flowID: UUID(), context: flow(), resume: { _ in }) else {
            Issue.record("expected allow")
            return
        }
        #expect(verdict.reason == .rule(rule.id))
    }

    @Test func oneAnswerCoversTCPAndUDP() {
        let (core, delegate) = makeCore()
        let released = Locked<[Verdict]>([])
        _ = core.decide(flowID: UUID(), context: flow(proto: .tcp), resume: { v in released.withLock { $0.append(v) } })
        _ = core.decide(flowID: UUID(), context: flow(proto: .udp), resume: { v in released.withLock { $0.append(v) } })
        #expect(delegate.alerts.current.count == 1) // HTTP/3 over UDP joins the HTTPS alert

        let alert = delegate.alerts.current[0]
        core.resolveAlert(alert.id, decision: AlertDecision(action: .allow))
        #expect(released.current.count == 2)
        let rule = try! #require(core.state.rules.last)
        #expect(rule.proto == .any)
        #expect(rule.ports == .single(443))
        #expect(rule.summary.hasSuffix("port 443"))

        // Neither asks again.
        for proto in [TransportProtocol.tcp, .udp] {
            guard case .allow = core.decide(flowID: UUID(), context: flow(proto: proto), resume: { _ in }) else {
                Issue.record("expected \(proto) to be allowed")
                return
            }
        }
        #expect(delegate.alerts.current.count == 1)
    }

    @Test func onceAnswersDontCreateRules() async {
        let (core, delegate) = makeCore()
        _ = core.decide(flowID: UUID(), context: flow(), resume: { _ in })
        let alert = delegate.alerts.current[0]
        let before = core.state.rules.count
        core.resolveAlert(alert.id, decision: AlertDecision(action: .deny, duration: .once))
        #expect(core.state.rules.count == before)
    }

    @Test func temporaryRulesGetExpirations() {
        let (core, _) = makeCore()
        let quit = core.makeRule(from: AlertDecision(action: .allow, duration: .untilQuit), context: flow())
        #expect(quit.expiration == .untilQuit(pid: 4242, startTime: 1))
        let timed = core.makeRule(from: AlertDecision(action: .allow, duration: .minutes(15)), context: flow())
        guard case .date(let end) = timed.expiration else { Issue.record("expected a date"); return }
        #expect(abs(end.timeIntervalSinceNow - 900) < 5)
        let anywhere = core.makeRule(from: AlertDecision(action: .deny, processScope: .anyProcess, remoteScope: .any, portScope: .anyPort, allUsers: false), context: flow())
        #expect(anywhere.process == .any)
        #expect(anywhere.remote == .any)
        #expect(anywhere.ports == .any)
        #expect(anywhere.userID == 501)
        #expect(anywhere.codeRequirement == nil)
    }

    @Test func unattendedActionAppliesWithoutClients() {
        let (core, delegate) = makeCore()
        delegate.acceptsAlerts = false
        #expect(core.decide(flowID: UUID(), context: flow(), resume: { _ in }) == .allow(Verdict(.allow, .unattended)))
    }

    @Test func modesAndProtectionSwitch() async {
        let (core, _) = makeCore()
        _ = await core.handle(.setMode(.silentDeny), client: app, authorization: nil)
        #expect(core.decide(flowID: UUID(), context: flow(), resume: { _ in }) == .deny(Verdict(.deny, .mode(.silentDeny))))
        _ = await core.handle(.setProtection(false), client: app, authorization: nil)
        #expect(core.decide(flowID: UUID(), context: flow(), resume: { _ in }) == .allow(Verdict(.allow, .protectionOff)))
    }

    @Test func signatureMismatchDeniesAllowRules() async {
        let (core, delegate) = makeCore()
        core.requirementChecker = { _, _ in .violated }
        var rule = Rule(action: .allow, process: .path(unknownApp.path), codeRequirement: "identifier \"com.example.tool\"")
        rule.remote = .any
        _ = await core.handle(.saveRule(rule), client: app, authorization: nil)
        guard case .deny(let verdict) = core.decide(flowID: UUID(), context: flow(), resume: { _ in }) else {
            Issue.record("expected deny")
            return
        }
        #expect(verdict.reason == .signatureMismatch(rule.id))
        _ = core.decide(flowID: UUID(), context: flow(), resume: { _ in })
        let notices = delegate.events.current.filter { if case .notice(let e) = $0 { e.kind == .signatureMismatch } else { false } }
        #expect(notices.count == 1) // once per process, not once per connection
    }

    @Test func programsUpdatedWhileRunningKeepTheirRules() async {
        let (core, _) = makeCore()
        core.requirementChecker = { _, _ in .unverifiable }
        var rule = Rule(action: .allow, process: .path(unknownApp.path), codeRequirement: unknownApp.designatedRequirement)
        rule.remote = .any
        _ = await core.handle(.saveRule(rule), client: app, authorization: nil)
        // Argus read the same signature when it first saw the process: still the same program.
        #expect(core.decide(flowID: UUID(), context: flow(), resume: { _ in }) == .allow(Verdict(.allow, .rule(rule.id))))
        // Nothing to go by: blocked, but not accused of being malware.
        var unread = unknownApp
        unread.designatedRequirement = nil
        guard case .deny(let verdict) = core.decide(flowID: UUID(), context: flow(unread), resume: { _ in }) else {
            Issue.record("expected deny")
            return
        }
        #expect(verdict.reason == .signatureMismatch(rule.id))
    }

    @Test func monitorModeObservesWithoutEnforcing() {
        let (core, _) = makeCore(host: .monitor)
        let verdict = core.observe(flowID: UUID(), context: flow())
        #expect(verdict == Verdict(.allow, .observed, enforced: false))
    }

    @Test func lockRequiresAuthorizationExceptForRoot() async {
        let (core, _) = makeCore()
        var settings = core.state.settings
        settings.lockEnabled = true
        _ = await core.handle(.updateSettings(settings), client: app, authorization: nil)

        guard case .error(.locked) = await core.handle(.setMode(.silentAllow), client: app, authorization: Data([1, 2])) else {
            Issue.record("expected the lock to refuse")
            return
        }
        guard case .state = await core.handle(.getState, client: app, authorization: nil) else {
            Issue.record("reads are always allowed")
            return
        }
        let root = ClientContext(userID: 0, pid: 1, role: .commandLine)
        guard case .state(let state) = await core.handle(.setMode(.silentAllow), client: root, authorization: nil) else {
            Issue.record("root may change locked settings")
            return
        }
        #expect(state.settings.mode == .silentAllow)
    }

    @Test func networksSwitchProfiles() async {
        let (core, _) = makeCore()
        let home = core.state.profiles[0]
        let network = NetworkIdentity(interface: .wifi, ssid: "Casa", gatewayAddress: "192.168.1.1", gatewayHardwareAddress: "aa:bb:cc:dd:ee:ff")
        guard case .network(let first) = await core.handle(.reportNetwork(network), client: app, authorization: nil) else { return }
        #expect(!first.isKnown)

        guard case .network(let assigned) = await core.handle(.assignNetwork(network, profileID: home.id), client: app, authorization: nil) else { return }
        #expect(assigned.isKnown)
        #expect(core.state.settings.activeProfileID == home.id)

        _ = await core.handle(.activateProfile(nil), client: app, authorization: nil)
        var sameRouter = network
        sameRouter.ssid = nil
        guard case .network(let again) = await core.handle(.reportNetwork(sameRouter), client: app, authorization: nil) else { return }
        #expect(again.switched)
        #expect(core.state.settings.activeProfileID == home.id)
    }

    @Test func deletingAProfileDeletesItsRules() async {
        let (core, _) = makeCore()
        let profile = core.state.profiles[0]
        _ = await core.handle(.saveRule(Rule(action: .deny, profileID: profile.id)), client: app, authorization: nil)
        _ = await core.handle(.deleteProfile(profile.id), client: app, authorization: nil)
        #expect(!core.state.rules.contains { $0.profileID == profile.id })
    }

    @Test func importsLocalRuleGroupsAndBlocks() async {
        let (core, _) = makeCore()
        let response = await core.handle(.importRuleGroup(name: "Local", contents: Data("ads.example.com\n".utf8), format: .domains),
                                         client: app, authorization: nil)
        guard case .state(let state) = response else { Issue.record("unexpected \(response)"); return }
        let group = try! #require(state.ruleGroups.first)
        #expect(group.domainCount == 1)
        guard case .deny(let verdict) = core.decide(flowID: UUID(), context: flow(host: "x.ads.example.com"), resume: { _ in }) else {
            Issue.record("expected the blocklist to deny")
            return
        }
        #expect(verdict.reason == .blocklist(group.id))
    }

    @Test func lookupsArentDroppedForTheirNameButTheConnectionIs() async {
        let (core, _) = makeCore()
        _ = await core.handle(.importRuleGroup(name: "Local", contents: Data("ads.example.com\n".utf8), format: .domains),
                              client: app, authorization: nil)
        // Safari looking up a listed name through the router gets its answer at once...
        let lookup = flow(safari, host: "x.ads.example.com", address: "192.168.1.1", port: 53, proto: .udp)
        #expect(lookup.isDNSLookup)
        #expect(core.decide(flowID: UUID(), context: lookup, resume: { _ in }) == .allow(Verdict(.allow, .localNetwork)))
        // ...and the connection to it is blocked.
        guard case .deny = core.decide(flowID: UUID(), context: flow(safari, host: "x.ads.example.com"), resume: { _ in }) else {
            Issue.record("expected the connection to be blocked")
            return
        }
        // A program Argus would have to ask about keeps the lookup blocked, rather than an alert per name.
        let unknownLookup = flow(unknownApp, host: "x.ads.example.com", address: "9.9.9.9", port: 53, proto: .udp)
        guard case .deny = core.decide(flowID: UUID(), context: unknownLookup, resume: { _ in }) else {
            Issue.record("expected the lookup to stay blocked")
            return
        }
        // So does a rule against the DNS server itself.
        _ = await core.handle(.saveRule(Rule(action: .deny, process: .path(safari.path), remote: .address("192.168.1.1"),
                                             ports: .single(53))), client: app, authorization: nil)
        guard case .deny = core.decide(flowID: UUID(), context: lookup, resume: { _ in }) else {
            Issue.record("expected the rule to block the lookup")
            return
        }
    }

    @Test func backupsRoundTrip() async throws {
        let (core, _) = makeCore()
        _ = await core.handle(.saveRule(Rule(action: .deny, remote: .host("x.com"))), client: app, authorization: nil)
        guard case .data(let backup) = await core.handle(.exportBackup, client: app, authorization: nil) else { return }
        let (other, _) = makeCore()
        _ = await other.handle(.importBackup(backup, merge: false), client: app, authorization: nil)
        #expect(other.state.rules.map(\.id) == core.state.rules.map(\.id))
    }

    @Test func mergingBackupsKeepsOneProfilePerName() async throws {
        let (core, _) = makeCore()
        let home = try #require(core.state.profiles.first { $0.name == "Home" })
        _ = await core.handle(.saveRule(Rule(action: .deny, remote: .host("x.com"), profileID: home.id)), client: app, authorization: nil)
        guard case .data(let backup) = await core.handle(.exportBackup, client: app, authorization: nil) else { return }
        let (other, _) = makeCore() // its own starter profiles, with different IDs
        _ = await other.handle(.importBackup(backup, merge: true), client: app, authorization: nil)
        #expect(other.state.profiles.map(\.name) == ["Home", "Public Wi-Fi"])
        #expect(other.state.rules.count == core.state.rules.count) // the starter rules aren't added twice
        let rule = try #require(other.state.rules.first { $0.remote == .host("x.com") })
        #expect(rule.profileID == other.state.profiles.first?.id)
    }

    @Test func emptyDuplicateProfilesAreDropped() {
        var state = FirewallState.initial()
        let used = Profile(name: "home")
        state.profiles += [Profile(name: "Public Wi-Fi"), used, Profile(name: "Work"), Profile(name: "Work")]
        state.rules.append(Rule(action: .allow, remote: .any, profileID: used.id))
        state.removeEmptyDuplicateProfiles()
        // The starter Home holds nothing while the imported "home" has a rule; one empty Work stays.
        #expect(state.profiles.map(\.name) == ["Public Wi-Fi", "home", "Work"])
    }

    @Test func statePersists() async {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("argus-persist-\(UUID())")
        let core = FirewallCore(host: .monitor, directory: directory)
        _ = await core.handle(.saveRule(Rule(action: .deny, remote: .host("persist.me"))), client: app, authorization: nil)
        core.flush()
        let reopened = FirewallCore(host: .monitor, directory: directory)
        #expect(reopened.state.rules.contains { $0.remote == .host("persist.me") })
    }
}

@Suite struct AlertTimingTests {
    @Test func countdownStartsWhenAnAlertIsShown() async throws {
        let (core, delegate) = makeCore()
        var settings = core.state.settings
        settings.alertTimeout = 0.3
        _ = await core.handle(.updateSettings(settings), client: app, authorization: nil)

        let released = Locked<Verdict?>(nil)
        _ = core.decide(flowID: UUID(), context: flow(), resume: { verdict in released.withLock { $0 = verdict } })
        let alert = try #require(delegate.alerts.current.first)
        #expect(alert.deadline!.timeIntervalSinceNow > 500) // queued: nobody has seen it yet

        try await Task.sleep(for: .milliseconds(600))
        #expect(released.current == nil) // waiting in the queue doesn't use up the timeout

        let shown = try #require(core.alertShown(alert.id))
        #expect(shown.deadline!.timeIntervalSinceNow < 1)
        try await Task.sleep(for: .milliseconds(900))
        #expect(released.current == Verdict(.deny, .alertTimeout))
        #expect(core.alertShown(alert.id) == nil)
    }
}

/// One answer for an app's many nameless servers.
@Suite struct WiderAnswerTests {
    func relay(_ address: String, _ port: UInt16) -> FlowContext { flow(host: nil, address: address, port: port, proto: .udp) }

    @Test func aWiderAnswerCoversWaitingAlertsAndReplacesEarlierOnes() async throws {
        let (core, delegate) = makeCore()
        // Three relays answered one at a time, the way it used to go.
        for (address, port) in [("162.254.193.98", UInt16(27031)), ("103.10.124.118", 27018), ("146.66.155.4", 27040)] {
            _ = core.decide(flowID: UUID(), context: relay(address, port), resume: { _ in })
            core.resolveAlert(try #require(core.pendingAlerts.first).id, decision: AlertDecision(action: .allow))
        }
        let before = core.state.rules
        let earlier = before.filter { $0.origin == .alert }
        #expect(earlier.count == 3)
        // An answer of the user's own for the same app, which no alert may take away.
        let byHand = Rule(action: .allow, process: .path(unknownApp.path), codeRequirement: unknownApp.designatedRequirement,
                          remote: .address("208.78.164.10"), ports: .single(27050), notes: "The lobby")
        _ = await core.handle(.saveRule(byHand), client: app, authorization: nil)

        // Three more arrive together.
        let released = Locked<[Verdict]>([])
        for (address, port) in [("155.133.252.87", UInt16(27024)), ("155.133.238.194", 27019), ("185.25.182.20", 27052)] {
            _ = core.decide(flowID: UUID(), context: relay(address, port), resume: { v in released.withLock { $0.append(v) } })
        }
        let waiting = core.pendingAlerts
        #expect(waiting.count == 3)
        let alert = try #require(waiting.first { $0.address == "155.133.252.87" })
        let pattern = try #require(alert.pattern(rules: core.state.rules, waiting: waiting))
        #expect(pattern == AlertPattern(servers: .any, ports: PortRange(27000, 27099)))

        let decision = AlertDecision(action: .allow, remoteScope: .any, portRange: pattern.ports)
        let others = Set(waiting.map(\.id)).subtracting([alert.id])
        #expect(alert.reach(of: decision, state: core.state, waiting: waiting) == AlertReach(alerts: others, rules: 3))
        #expect(alert.reach(of: AlertDecision(action: .allow), state: core.state, waiting: waiting).isEmpty)
        var once = decision
        once.duration = .once
        #expect(alert.reach(of: once, state: core.state, waiting: waiting).isEmpty)
        var forAWhile = decision
        forAWhile.duration = .minutes(15)
        #expect(alert.reach(of: forAWhile, state: core.state, waiting: waiting) == AlertReach(alerts: others))
        // A network takes in the neighbour and none of the earlier answers elsewhere.
        let network = AlertDecision(action: .allow, remoteScope: .address, portScope: .anyPort, networkPrefix: 16)
        #expect(alert.reach(of: network, state: core.state, waiting: waiting).alerts.count == 1)
        #expect(alert.reach(of: network, state: core.state, waiting: waiting).rules == 0)

        guard case .ok = await core.handle(.resolveAlert(alert.id, decision), client: app, authorization: nil) else {
            Issue.record("expected the answer to be accepted")
            return
        }
        #expect(released.current.count == 3) // the two others had their answer too
        #expect(released.current.allSatisfy { $0.action == .allow })
        #expect(core.pendingAlerts.isEmpty)
        let rule = try #require(core.state.rules.last)
        #expect(rule.remote == .any)
        #expect(rule.ports == .ranges([PortRange(27000, 27099)]))
        #expect(rule.process == .path(unknownApp.path))
        #expect(core.state.rules.filter { $0.origin == .alert }.map(\.id) == [rule.id]) // one rule where there were three
        #expect(core.state.rules.contains { $0.id == byHand.id })
        #expect(core.recentChanges.first?.summary == "Allowed from an alert: \(rule.summary), in place of 3 rules it covers")

        // The next relay doesn't ask, and neither does one of the old ones.
        #expect(core.decide(flowID: UUID(), context: relay("190.217.33.5", 27060), resume: { _ in }) == .allow(Verdict(.allow, .rule(rule.id))))
        #expect(core.decide(flowID: UUID(), context: relay("162.254.193.98", 27031), resume: { _ in }) == .allow(Verdict(.allow, .rule(rule.id))))
        #expect(delegate.alerts.current.count == 6)
        // Other ports still ask.
        guard case .pause = core.decide(flowID: UUID(), context: relay("190.217.33.5", 443), resume: { _ in }) else {
            Issue.record("expected an alert for another port")
            return
        }

        // Undo puts the three answers back and takes the wider rule away.
        _ = await core.handle(.undoChange(try #require(core.recentChanges.first).id), client: app, authorization: nil)
        #expect(Set(core.state.rules.map(\.id)) == Set(before.map(\.id) + [byHand.id]))
    }

    @Test func aTemporaryAnswerReplacesNothing() async throws {
        let (core, delegate) = makeCore() // the core holds its delegate weakly; without one nobody is asked
        defer { withExtendedLifetime(delegate) {} }
        _ = core.decide(flowID: UUID(), context: relay("162.254.193.98", 27031), resume: { _ in })
        core.resolveAlert(try #require(core.pendingAlerts.first).id, decision: AlertDecision(action: .allow))
        let kept = try #require(core.state.rules.last)
        // A deny doesn't take allows away.
        _ = core.decide(flowID: UUID(), context: relay("155.133.252.87", 9000), resume: { _ in })
        core.resolveAlert(try #require(core.pendingAlerts.first).id,
                          decision: AlertDecision(action: .deny, remoteScope: .address, portScope: .anyPort, networkPrefix: 16))
        #expect(core.state.rules.last?.remote == .address("155.133.0.0/16"))
        #expect(core.state.rules.contains { $0.id == kept.id })
        // Nor does an allow that ends: the earlier answer is still there when the quarter of an hour is up.
        _ = core.decide(flowID: UUID(), context: relay("146.66.155.4", 27040), resume: { _ in })
        core.resolveAlert(try #require(core.pendingAlerts.first).id,
                          decision: AlertDecision(action: .allow, remoteScope: .any, portScope: .anyPort, duration: .minutes(15)))
        #expect(core.state.rules.last?.remote == .any)
        #expect(core.state.rules.contains { $0.id == kept.id })
    }
}
