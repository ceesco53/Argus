import Foundation
import Testing
@testable import ArgusKit

@Suite struct UndoTests {
    @Test func undoReversesOnlyThatChange() async throws {
        let (core, delegate) = makeCore()
        let rule = Rule(action: .allow, process: .path(unknownApp.path), remote: .host("news.example.com"))
        _ = await core.handle(.saveRule(rule), client: app, authorization: nil)
        _ = await core.handle(.setMode(.silentDeny), client: app, authorization: nil)
        var settings = core.state.settings
        settings.allowSignedSoftware = true
        _ = await core.handle(.updateSettings(settings), client: app, authorization: nil)

        let changes = core.recentChanges
        #expect(changes.map(\.summary) == ["Changed allowing identified developers", "Mode: Ask Me → Deny Silently",
                                           "Added rule: \(rule.summary)"])
        #expect(delegate.events.current.contains { if case .changeRecorded = $0 { true } else { false } })

        // Undo the mode change; the later settings change survives.
        _ = await core.handle(.undoChange(changes[1].id), client: app, authorization: nil)
        #expect(core.state.settings.mode == .alert)
        #expect(core.state.settings.allowSignedSoftware)
        #expect(core.state.rules.contains { $0.id == rule.id })

        // Undo adding the rule.
        _ = await core.handle(.undoChange(changes[2].id), client: app, authorization: nil)
        #expect(!core.state.rules.contains { $0.id == rule.id })
        guard case .error(.invalid) = await core.handle(.undoChange(changes[2].id), client: app, authorization: nil) else {
            Issue.record("a change can only be undone once")
            return
        }

        // Undoing the undo brings the rule back.
        let undoRecord = try #require(core.recentChanges.first)
        #expect(undoRecord.summary.hasPrefix("Undid: Added rule"))
        _ = await core.handle(.undoChange(undoRecord.id), client: app, authorization: nil)
        #expect(core.state.rules.contains { $0.id == rule.id })
    }

    @Test func deletedRulesComeBack() async {
        let (core, _) = makeCore()
        let original = core.state.rules
        _ = await core.handle(.deleteRules(original.map(\.id)), client: app, authorization: nil)
        #expect(core.state.rules.isEmpty)
        #expect(core.recentChanges.first?.summary == "Deleted \(original.count) rules")
        _ = await core.handle(.undoChange(core.recentChanges[0].id), client: app, authorization: nil)
        #expect(Set(core.state.rules.map(\.id)) == Set(original.map(\.id)))
    }

    @Test func downloadsAreNotChanges() async {
        let (core, _) = makeCore()
        _ = await core.handle(.importRuleGroup(name: "Local", contents: Data("ads.example.com\n".utf8), format: .domains), client: app, authorization: nil)
        #expect(core.recentChanges.map(\.summary) == ["Imported “Local”"])
    }
}

@Suite struct LearningAndBusyTests {
    @Test func learningAllowsQuietlyAndRecords() async {
        let (core, delegate) = makeCore()
        _ = await core.handle(.setLearning(until: Date().addingTimeInterval(3 * 86_400)), client: app, authorization: nil)
        #expect(core.decide(flowID: UUID(), context: flow(), resume: { _ in }) == .allow(Verdict(.allow, .learning)))
        #expect(delegate.alerts.current.isEmpty)
        #expect(core.activity.snapshot(since: 0).processes.first?.unapprovedCount == 1)

        _ = await core.handle(.setLearning(until: nil), client: app, authorization: nil)
        guard case .pause = core.decide(flowID: UUID(), context: flow(), resume: { _ in }) else {
            Issue.record("alerts are back after learning ends")
            return
        }
    }

    @Test func busyDecidesWithoutAsking() async {
        let (core, delegate) = makeCore()
        _ = await core.handle(.setBusy(true), client: app, authorization: nil)
        #expect(core.decide(flowID: UUID(), context: flow(), resume: { _ in }) == .allow(Verdict(.allow, .deferred)))

        var settings = core.state.settings
        settings.busyAction = .deny
        _ = await core.handle(.updateSettings(settings), client: app, authorization: nil)
        #expect(core.decide(flowID: UUID(), context: flow(host: "b.example.com"), resume: { _ in }) == .deny(Verdict(.deny, .deferred)))

        // A confident suggestion wins over the busy setting: Chrome talking to google.com.
        let chrome = ProcessIdentity(path: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", name: "Google Chrome",
                                     bundleIdentifier: "com.google.Chrome", signature: .developerID)
        #expect(core.decide(flowID: UUID(), context: flow(chrome, host: "clients4.google.com"), resume: { _ in }) == .allow(Verdict(.allow, .deferred)))
        #expect(delegate.alerts.current.isEmpty)
    }
}

@Suite struct ConnectionTestTests {
    @Test func explainsWhatWouldHappen() async {
        let (core, _) = makeCore()
        let rule = Rule(action: .deny, process: .path(unknownApp.path), remote: .domain("example.com"))
        _ = await core.handle(.saveRule(rule), client: app, authorization: nil)
        _ = await core.handle(.importRuleGroup(name: "Trackers", contents: Data("tracker.io\n".utf8), format: .domains), client: app, authorization: nil)

        let blocked = core.test(ConnectionTest(processPath: unknownApp.path, host: "www.example.com"), userID: 501)
        #expect(blocked.verdict?.action == .deny)
        #expect(blocked.ruleID == rule.id)
        #expect(blocked.explanation.hasPrefix("Rule: Deny Tool"))

        let listed = core.test(ConnectionTest(processPath: nil, host: "eu.tracker.io"), userID: 501)
        #expect(listed.blocklistName == "Trackers")

        let unknown = core.test(ConnectionTest(processPath: unknownApp.path, host: "other.org"), userID: 501)
        #expect(unknown.verdict == nil)
        #expect(unknown.explanation == "No rule covers this; Argus would ask you")
        #expect(core.pendingAlerts.isEmpty) // a test never creates an alert
    }
}

@Suite struct DigestAndUsageTests {
    @Test func digestCountsAcrossDays() {
        let tracker = ActivityTracker()
        let yesterday = Date().addingTimeInterval(-86_400)
        tracker.recordConnection(flowID: nil, context: flow(host: "ads.tracker.io"), verdict: Verdict(.deny, .blocklist(UUID())), now: yesterday)
        tracker.recordConnection(flowID: nil, context: flow(host: "px.tracker.io"), verdict: Verdict(.deny, .blocklist(UUID())), now: Date())
        tracker.recordConnection(flowID: nil, context: flow(curl, host: "api.example.com"), verdict: Verdict(.allow, .appleSoftware), now: Date())

        let digest = tracker.digest(days: 7)
        #expect(digest.days.count == 2)
        #expect(digest.blocked == 2)
        #expect(digest.connections == 3)
        #expect(digest.topBlockedDomains == [NamedCount(name: "tracker.io", count: 2)])
        #expect(digest.topBlockedApps.first == NamedCount(name: "Tool", count: 2))
        #expect(Set(digest.newApps) == ["Tool", "curl"])
    }

    @Test func usageTodayPerProgram() {
        let tracker = ActivityTracker()
        let id = UUID()
        tracker.recordConnection(flowID: id, context: flow(), verdict: Verdict(.allow, .appleSoftware))
        tracker.updateFlow(id, totalIn: 3_000_000, totalOut: 1_000_000, closed: false)
        let usage = tracker.usageToday()
        #expect(usage.count == 1)
        #expect(usage.first?.name == "Tool")
        #expect(usage.first?.bytes == 4_000_000)
    }
}

@Suite struct RuleAnalysisTests {
    @Test func findsDuplicatesAndOverruledRules() {
        let first = Rule(action: .allow, process: .path(unknownApp.path), remote: .host("api.example.com"), createdAt: Date(timeIntervalSince1970: 1))
        let copy = Rule(action: .allow, process: .path(unknownApp.path), remote: .host("API.example.com"), notes: "again", createdAt: Date(timeIntervalSince1970: 2))
        let deny = Rule(action: .deny, process: .path(unknownApp.path), remote: .host("api.example.com"), createdAt: Date(timeIntervalSince1970: 3))
        let other = Rule(action: .allow, process: .path(unknownApp.path), remote: .host("api.example.com"), ports: .single(443))
        let issues = RuleAnalysis.issues(in: [deny, copy, first, other])
        #expect(issues[copy.id] == .duplicate(of: first.id))
        #expect(issues[first.id] == .overruled(by: deny.id))
        #expect(issues[deny.id] == nil)
        #expect(issues[other.id] == nil) // a port makes it narrower, so it can win
    }

    func answer(_ remote: RemoteMatch, _ ports: PortMatch = .single(27024), _ action: RuleAction = .allow, origin: RuleOrigin = .alert) -> Rule {
        Rule(action: action, process: .path(unknownApp.path), codeRequirement: unknownApp.designatedRequirement, remote: remote,
             ports: ports, origin: origin)
    }

    @Test func findsRulesABroaderRuleCovers() {
        let relays = (1...3).map { answer(.address("155.133.252.\($0)"), .single(27020 + UInt16($0))) }
        let elsewhere = answer(.address("155.133.252.9"), .single(443))
        let named = answer(.host("api.example.com"), .single(27024))
        let stretch = answer(.any, .ranges([PortRange(27000, 27099)]))
        let rules = relays + [elsewhere, named, stretch]
        let issues = RuleAnalysis.issues(in: rules)
        for relay in relays { #expect(issues[relay.id] == .covered(by: stretch.id)) }
        #expect(issues[named.id] == .covered(by: stretch.id))
        #expect(issues[elsewhere.id] == nil) // another port
        #expect(issues[stretch.id] == nil)
        #expect(issues.values.allSatisfy { $0.isRedundant })
        #expect(Set(RuleAnalysis.answersReplaced(by: stretch, in: rules)) == Set(relays.map(\.id) + [named.id]))

        // A network covers its addresses, a domain its hosts, and a host on any port the host on one.
        let network = answer(.address("155.133.0.0/16"), .any)
        #expect(RuleAnalysis.issues(in: [relays[0], network, answer(.address("162.254.193.98"))]) == [relays[0].id: .covered(by: network.id)])
        let domain = answer(.domain("example.com"))
        #expect(RuleAnalysis.issues(in: [named, domain, answer(.host("api.example.org"))]) == [named.id: .covered(by: domain.id)])
        let everyPort = answer(.host("api.example.com"), .any)
        #expect(RuleAnalysis.issues(in: [named, everyPort]) == [named.id: .covered(by: everyPort.id)])
    }

    @Test func aCoveredRuleStaysWhileItMakesADifference() {
        let relay = answer(.address("155.133.252.1"))
        let anywhere = answer(.any, .any)
        #expect(RuleAnalysis.issues(in: [relay, anywhere])[relay.id] == .covered(by: anywhere.id))
        func stays(_ rules: [Rule], alongside others: [Rule] = []) -> Bool {
            RuleAnalysis.issues(in: rules, alongside: others)[relay.id] == nil
                && !RuleAnalysis.answersReplaced(by: anywhere, in: rules, alongside: others).contains(relay.id)
        }
        // A deny between the two would decide once the relay's rule is gone: for its network, or
        // from a rule group, or for a helper Argus files under the app.
        #expect(stays([relay, anywhere, answer(.address("155.133.0.0/16"), .any, .deny)]))
        #expect(stays([relay, anywhere], alongside: [answer(.address("155.133.0.0/16"), .any, .deny, origin: .ruleGroup(UUID()))]))
        let helper = unknownApp.path.replacingOccurrences(of: "/Contents/MacOS/Tool", with: "/Contents/Frameworks/Helper.app/Contents/MacOS/Helper")
        #expect(stays([relay, anywhere, Rule(action: .deny, process: .path(helper), remote: .address("155.133.252.0/24"))]))
        // A deny that can't touch it changes nothing: another server, another app, or every app
        // (which any rule for this app outranks).
        for deny in [answer(.address("162.254.0.0/16"), .any, .deny), Rule(action: .deny, process: .path(safari.path), remote: .address("155.133.0.0/16")),
                     Rule(action: .deny, remote: .address("155.133.0.0/16"))] {
            #expect(!stays([relay, anywhere, deny]))
        }
        // The broader rule has to last, apply wherever the narrow one does, and check the same signature.
        var temporary = anywhere
        temporary.expiration = .date(Date().addingTimeInterval(900))
        var oneProfile = anywhere
        oneProfile.profileID = UUID()
        var oneUser = anywhere
        oneUser.userID = 502
        var unsigned = anywhere
        unsigned.codeRequirement = nil
        var off = anywhere
        off.isEnabled = false
        var incoming = anywhere
        incoming.direction = .incoming
        for broader in [temporary, oneProfile, oneUser, unsigned, off, incoming, answer(.any, .any, .deny)] {
            #expect(RuleAnalysis.issues(in: [relay, broader])[relay.id] == nil)
            #expect(RuleAnalysis.answersReplaced(by: broader, in: [relay]).isEmpty)
        }
        // A temporary narrow rule is covered all the same.
        var untilRestart = relay
        untilRestart.expiration = .untilRestart(bootSession: "x")
        #expect(RuleAnalysis.answersReplaced(by: anywhere, in: [untilRestart]) == [relay.id])
    }

    @Test func onlyPlainAlertAnswersAreReplaced() {
        let anywhere = answer(.any, .any)
        let byHand = answer(.address("155.133.252.1"), origin: .user)
        var annotated = answer(.address("155.133.252.2"))
        annotated.notes = "the relay in Stockholm"
        let plain = answer(.address("155.133.252.3"))
        #expect(RuleAnalysis.answersReplaced(by: anywhere, in: [byHand, annotated, plain, anywhere]) == [plain.id])
        // Rules still points the others out.
        #expect(Set(RuleAnalysis.issues(in: [byHand, annotated, plain, anywhere]).keys) == [byHand.id, annotated.id, plain.id])
        // Rules for every program are left alone: a blocklist entry could rank between them.
        let everyApp = Rule(action: .allow, remote: .any, origin: .alert)
        let oneServer = Rule(action: .allow, remote: .host("api.example.com"), origin: .alert)
        #expect(RuleAnalysis.issues(in: [everyApp, oneServer]).isEmpty)
        #expect(RuleAnalysis.answersReplaced(by: everyApp, in: [oneServer]).isEmpty)
    }
}

@Suite struct BatchTests {
    @Test func savingSeveralRulesIsOneChange() async {
        let (core, _) = makeCore()
        let rules = ["a.example.com", "b.example.com", "c.example.com"].map { Rule(action: .allow, process: .path(unknownApp.path), remote: .host($0)) }
        _ = await core.handle(.saveRules(rules), client: app, authorization: nil)
        #expect(core.recentChanges.first?.summary == "Added 3 rules")
        _ = await core.handle(.undoChange(core.recentChanges[0].id), client: app, authorization: nil)
        #expect(!core.state.rules.contains { rules.map(\.id).contains($0.id) })
    }

    @Test func startingToLearnReleasesWaitingAlerts() async {
        let (core, delegate) = makeCore() // keep the alert presenter alive; the core holds it weakly
        defer { withExtendedLifetime(delegate) {} }
        let released = Locked<Verdict?>(nil)
        _ = core.decide(flowID: UUID(), context: flow(), resume: { v in released.withLock { $0 = v } })
        _ = await core.handle(.setLearning(until: Date().addingTimeInterval(86_400)), client: app, authorization: nil)
        #expect(released.current == Verdict(.allow, .learning))
        #expect(core.pendingAlerts.isEmpty)
    }
}

@Suite struct SyncSafetyTests {
    @Test func massRemovalsNeedConfirmation() {
        #expect(!SyncSafety.needsConfirmation(removing: 1, of: 2)) // deleting a rule or two is ordinary
        #expect(!SyncSafety.needsConfirmation(removing: 5, of: 5))
        #expect(!SyncSafety.needsConfirmation(removing: 12, of: 200))
        #expect(SyncSafety.needsConfirmation(removing: 182, of: 186)) // what wiped a configuration once
        #expect(SyncSafety.needsConfirmation(removing: 6, of: 10))
    }
}
