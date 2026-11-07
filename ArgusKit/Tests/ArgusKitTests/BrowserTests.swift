import Foundation
import Testing
@testable import ArgusKit

/// Chrome, its versioned network helper, and an Electron app, as Argus sees them.
enum Chrome {
    static let bundle = "/Applications/Google Chrome.app"
    static let app = ProcessIdentity(path: bundle + "/Contents/MacOS/Google Chrome", name: "Google Chrome",
                                     bundleIdentifier: "com.google.Chrome", appBundlePath: bundle, signature: .developerID,
                                     designatedRequirement: "identifier \"com.google.Chrome\" and anchor apple generic")
    static func helper(version: String = "156.0.8078.80") -> ProcessIdentity {
        let path = bundle + "/Contents/Frameworks/Google Chrome Framework.framework/Versions/\(version)/Helpers/"
            + "Google Chrome Helper (Aperitif).app/Contents/MacOS/Google Chrome Helper (Aperitif)"
        return ProcessIdentity(path: path, name: "Google Chrome Helper (Aperitif)", bundleIdentifier: "com.google.Chrome.helper",
                               appBundlePath: bundle, signature: .developerID,
                               designatedRequirement: "identifier \"com.google.Chrome.helper\" and anchor apple generic")
    }

    /// A connection Chrome's helper (pid 4242) makes for Chrome (pid 900).
    static func connection(host: String = "securepubads.g.doubleclick.net", version: String = "156.0.8078.80") -> FlowContext {
        flow(helper(version: version), host: host).attributingHelperTraffic(
            responsiblePID: { $0 == 4242 ? 900 : nil }, identity: { _ in app })
    }
}

@Suite struct HelperAttributionTests {
    @Test func bundledHelpersAreRecognised() {
        #expect(Chrome.helper().isBundledHelper)
        #expect(!Chrome.app.isBundledHelper)
        #expect(ProcessIdentity.isBundledHelper("/Applications/Foo.app/Contents/XPCServices/Bar.xpc/Contents/MacOS/Bar"))
        #expect(!ProcessIdentity.isBundledHelper("/usr/bin/curl"))
        #expect(!ProcessIdentity.isBundledHelper(WebKitAttributionTests.webKit.path))
        #expect(Chrome.app.isMainProgram(ofApp: Chrome.bundle))
        #expect(!Chrome.helper().isMainProgram(ofApp: Chrome.bundle))
    }

    @Test func browserHelperTrafficIsFiledUnderTheBrowser() {
        let context = Chrome.connection()
        #expect(context.process.path == Chrome.app.path)
        #expect(context.via?.path == Chrome.helper().path)
        #expect(context.viaIsHelper)
        #expect(context.pid == 900)
    }

    @Test func helpersRunByAnotherProgramKeepTheirOwnIdentity() {
        // Started by launchd (a login item), or by an app from a different bundle.
        let byItself = flow(Chrome.helper()).attributingHelperTraffic(responsiblePID: { $0 }, identity: { _ in Chrome.app })
        #expect(byItself.process.path == Chrome.helper().path && byItself.via == nil)
        let byOther = flow(Chrome.helper()).attributingHelperTraffic(responsiblePID: { _ in 900 }, identity: { _ in safari })
        #expect(byOther.process.path == Chrome.helper().path && byOther.via == nil)
        // Apps that aren't helpers are never re-filed, even when something else is responsible.
        let terminalCurl = flow(curl).attributingHelperTraffic(responsiblePID: { _ in 900 }, identity: { _ in Chrome.app })
        #expect(terminalCurl.process.path == curl.path)
    }

    @Test func rulesForChromeSurviveAChromeUpdate() {
        let blockAds = Rule(action: .deny, process: .path(Chrome.app.path), remote: .domain("doubleclick.net"))
        let set = CompiledRuleSet(rules: [blockAds], activeProfile: nil, blocklists: [])
        #expect(set.evaluate(Chrome.connection())?.rule?.id == blockAds.id)
        #expect(set.evaluate(Chrome.connection(version: "157.0.1.2"))?.rule?.id == blockAds.id)

        // A rule written for the old helper still applies to that helper, but not after an update.
        let helperRule = Rule(action: .deny, process: .path(Chrome.helper().path), remote: .domain("doubleclick.net"))
        let old = CompiledRuleSet(rules: [helperRule], activeProfile: nil, blocklists: [])
        #expect(old.evaluate(Chrome.connection())?.rule?.id == helperRule.id)
        #expect(old.evaluate(Chrome.connection(version: "157.0.1.2")) == nil)
    }
}

@Suite struct HelperRuleMoveTests {
    static func installed(_ bundle: String) -> ProcessIdentity? { bundle == Chrome.bundle ? Chrome.app : nil }

    @Test func helperRulesMoveToTheirApp() {
        let deny = Rule(action: .deny, process: .path(Chrome.helper().path), codeRequirement: Chrome.helper().designatedRequirement,
                        remote: .domain("taboola.com"), notes: "From an alert", createdAt: Date(timeIntervalSince1970: 1))
        let oldVersion = Rule(action: .allow, process: .path(Chrome.helper(version: "155.0.1.1").path), remote: .host("news.example.com"),
                              createdAt: Date(timeIntervalSince1970: 2))
        let move = RuleAnalysis.movingHelperRules([deny, oldVersion], app: HelperRuleMoveTests.installed)
        #expect(move.moved.map(\.id) == [deny.id, oldVersion.id])
        #expect(move.moved.allSatisfy { $0.process == .path(Chrome.app.path) })
        #expect(move.moved[0].codeRequirement == Chrome.app.designatedRequirement)
        #expect(move.moved[0].notes == "From an alert · Moved from Google Chrome Helper (Aperitif)")
        #expect(move.moved[1].codeRequirement == nil) // wasn't pinned, stays unpinned
        #expect(move.apps == ["Google Chrome": 2])
    }

    @Test func duplicatesAreDroppedAndOthersLeftAlone() {
        let existing = Rule(action: .deny, process: .path(Chrome.app.path), remote: .domain("taboola.com"), createdAt: Date(timeIntervalSince1970: 0))
        let same = Rule(action: .deny, process: .path(Chrome.helper().path), remote: .domain("taboola.com"), createdAt: Date(timeIntervalSince1970: 1))
        let sameOldVersion = Rule(action: .deny, process: .path(Chrome.helper(version: "155.0.1.1").path), remote: .domain("outbrain.com"),
                                  createdAt: Date(timeIntervalSince1970: 2))
        let sameNewVersion = Rule(action: .deny, process: .path(Chrome.helper().path), remote: .domain("outbrain.com"), createdAt: Date(timeIntervalSince1970: 3))
        let untilQuit = Rule(action: .allow, process: .path(Chrome.helper().path), expiration: .untilQuit(pid: 4242, startTime: 1))
        let notInstalled = Rule(action: .allow, process: .path("/Applications/Gone.app/Contents/Frameworks/Gone Helper.app/Contents/MacOS/Gone Helper"))
        let loginItem = Rule(action: .allow, process: .path(Chrome.bundle + "/Contents/Library/LoginItems/Updater.app/Contents/MacOS/Updater"))
        let plain = Rule(action: .allow, process: .path(curl.path))
        let move = RuleAnalysis.movingHelperRules([existing, same, sameOldVersion, sameNewVersion, untilQuit, notInstalled, loginItem, plain],
                                                  app: HelperRuleMoveTests.installed)
        #expect(move.duplicates == [same.id, sameNewVersion.id])
        #expect(move.moved.map(\.id) == [sameOldVersion.id])
        #expect(move.count == 3)

        // A login item moves once its connections were seen filed under the app.
        let seen = RuleAnalysis.movingHelperRules([loginItem], app: HelperRuleMoveTests.installed, seenFiledUnderApp: [loginItem.process.path!])
        #expect(seen.moved.map(\.id) == [loginItem.id])
    }

    @Test func movingIsOneUndoableChange() async {
        let (core, _) = makeCore()
        let helperRule = Rule(action: .deny, process: .path(Chrome.helper().path), remote: .domain("taboola.com"))
        let duplicate = Rule(action: .deny, process: .path(Chrome.helper(version: "155.0.1.1").path), remote: .domain("taboola.com"))
        _ = await core.handle(.saveRules([helperRule, duplicate]), client: app, authorization: nil)
        let move = RuleAnalysis.movingHelperRules(core.state.rules, app: HelperRuleMoveTests.installed)
        _ = await core.handle(.changeRules(save: move.moved, delete: move.duplicates, summary: "Moved 2 rules to Google Chrome"),
                              client: app, authorization: nil)
        #expect(core.state.rules.filter { $0.process == .path(Chrome.app.path) }.count == 1)
        #expect(!core.state.rules.contains { $0.process.path?.contains("Helper") == true })
        #expect(core.recentChanges.first?.summary == "Moved 2 rules to Google Chrome")

        _ = await core.handle(.undoChange(core.recentChanges.first!.id), client: app, authorization: nil)
        #expect(Set(core.state.rules.compactMap(\.process.path)).isSuperset(of: [Chrome.helper().path, Chrome.helper(version: "155.0.1.1").path]))
        #expect(!core.state.rules.contains { $0.process == .path(Chrome.app.path) })
    }
}

@Suite struct CulpritSearchTests {
    /// Runs a search where the page works whenever `needed` are all let through.
    static func search(_ blocked: [String], needing needed: Set<String>) -> (CulpritSearch.Outcome?, tests: Int) {
        guard var search = CulpritSearch(blocked: blocked) else { return (nil, 0) }
        while search.outcome == nil, search.step < 50 {
            search.record(pageWorked: needed.isSubset(of: Set(search.testing)))
        }
        return (search.outcome, search.step - 1)
    }

    @Test func findsTheOneServerAPageNeeds() {
        let blocked = ["a.ads.com", "html-load.com", "b.ads.com", "c.track.net", "d.track.net", "e.cdn.org", "f.cdn.org", "g.x.com"]
        let (outcome, tests) = CulpritSearchTests.search(blocked, needing: ["html-load.com"])
        #expect(outcome == .found(["html-load.com"]))
        #expect(tests <= 1 + 2 * 3) // the first check, then at most two per halving
    }

    @Test func pagesThatNeedSeveralServers() {
        let (outcome, _) = CulpritSearchTests.search(["a", "b", "c", "d"], needing: ["a", "d"])
        #expect(outcome == .found(["a", "b", "c", "d"]))
        let (sameHalf, _) = CulpritSearchTests.search(["a", "b", "c", "d"], needing: ["c", "d"])
        #expect(sameHalf == .found(["c", "d"]))
    }

    @Test func notArgusWhenLettingEverythingThroughDoesntHelp() {
        let (outcome, tests) = CulpritSearchTests.search(["a", "b"], needing: ["elsewhere"])
        #expect(outcome == .notArgus && tests == 1)
        #expect(CulpritSearch(blocked: []) == nil)
        #expect(CulpritSearch(blocked: ["a", "a"])?.suspects == ["a"])
    }
}

/// Safari as Argus sees it, bundle identifier and all.
let safariApp = WebKitAttributionTests.safari

@Suite struct BrowserScopeTests {
    static let ads = CompiledBlocklist(domains: DomainSet(suffixes: ["doubleclick.net", "ad.doubleclick.net", "taboola.com"]))

    @Test func browsersAreRecognised() {
        #expect(Browsers.isBrowser(safariApp))
        #expect(Browsers.browser(bundleIdentifier: "com.google.Chrome.canary")?.name == "Google Chrome")
        #expect(Browsers.browser(bundleIdentifier: "com.google.Chrome.helper") != nil)
        #expect(Browsers.browser(bundleIdentifier: "com.google.Chromecast") == nil)
        #expect(!Browsers.isBrowser(curl))
        #expect(Chrome.connection().isBrowser)
        #expect(WebKitAttributionTests.attributed().isBrowser)
    }

    @Test func browserListsLeaveOtherAppsAlone() {
        let list = UUID()
        let set = CompiledRuleSet(rules: [], activeProfile: nil, blocklists: [(list, BrowserScopeTests.ads)], browsersOnly: [list])
        #expect(set.evaluate(flow(safariApp, host: "securepubads.g.doubleclick.net"))?.blocklistID == list)
        #expect(set.evaluate(Chrome.connection())?.blocklistID == list)
        #expect(set.evaluate(flow(unknownApp, host: "securepubads.g.doubleclick.net")) == nil)

        let everywhere = CompiledRuleSet(rules: [], activeProfile: nil, blocklists: [(list, BrowserScopeTests.ads)])
        #expect(everywhere.evaluate(flow(unknownApp, host: "securepubads.g.doubleclick.net"))?.blocklistID == list)
    }

    @Test func adDomainsAllowsAreExceptionsToEveryList() {
        let list = UUID()
        var group = RuleGroup.adDomains()
        try? group.apply([AdDomainDecision(.domain("doubleclick.net"), .allow), AdDomainDecision(.domain("outbrain.com"), .deny)], now: Date())
        let set = CompiledRuleSet(rules: group.rules, activeProfile: nil, blocklists: [(list, BrowserScopeTests.ads)],
                                  browsersOnly: [list, group.id])
        // The list's ad.doubleclick.net entry is deeper than the allow, and still loses to it.
        let allowed = set.evaluate(flow(safariApp, host: "x.ad.doubleclick.net"))
        #expect(allowed?.action == .allow && allowed?.rule?.remote == .domain("doubleclick.net"))
        #expect(set.evaluate(flow(safariApp, host: "widgets.outbrain.com"))?.action == .deny)
        #expect(set.evaluate(flow(safariApp, host: "trc.taboola.com"))?.blocklistID == list)
        // Ad Domains is for browsers: other apps are untouched by either.
        #expect(set.evaluate(flow(unknownApp, host: "widgets.outbrain.com")) == nil)
        // A rule for the browser itself still outranks Ad Domains.
        let mine = Rule(action: .allow, process: .path(safariApp.path), remote: .host("widgets.outbrain.com"))
        let withMine = CompiledRuleSet(rules: group.rules + [mine], activeProfile: nil, blocklists: [], browsersOnly: [group.id])
        #expect(withMine.evaluate(flow(safariApp, host: "widgets.outbrain.com"))?.rule?.id == mine.id)
    }

    @Test func olderSavedGroupsStillLoad() throws {
        let group = RuleGroup(name: "Old", url: URL(string: "https://example.com/list.txt"))
        var json = try JSONSerialization.jsonObject(with: JSONEncoder().encode(group)) as! [String: Any]
        json.removeValue(forKey: "appliesTo")
        json.removeValue(forKey: "modifiedAt")
        let decoded = try JSONDecoder().decode(RuleGroup.self, from: JSONSerialization.data(withJSONObject: json))
        #expect(decoded.appliesTo == nil && !decoded.isBrowsersOnly)
    }

    @Test func adLevelsFollowTheBrowserList() {
        var state = FirewallState()
        #expect(state.browserAdLevel == .off)
        let entry = try! #require(BrowserAdLevel.normal.catalogEntry)
        state.ruleGroups.append(RuleGroup(name: entry.displayName, url: entry.url, catalogID: entry.id, appliesTo: .browsers))
        #expect(state.browserAdLevel == .normal)
        state.ruleGroups[0].isEnabled = false
        #expect(state.browserAdLevel == .off)
        // The same list for every app isn't the browser list.
        state.ruleGroups[0] = RuleGroup(name: entry.displayName, url: entry.url, catalogID: entry.id)
        #expect(state.browserAdGroup == nil)
    }
}

@Suite struct AdDomainsTests {
    @Test func decisionsReplaceEachOtherAndCanBeUndone() async throws {
        let (core, _) = makeCore()
        let chromeDeny = Rule(action: .deny, process: .path(Chrome.app.path), remote: .domain("taboola.com"), ports: .single(443))
        _ = await core.handle(.saveRule(chromeDeny), client: app, authorization: nil)

        _ = await core.handle(.decideAdDomains([AdDomainDecision(.domain("Taboola.com"), .deny)], removingRules: [chromeDeny.id]),
                              client: app, authorization: nil)
        let blocked = core.recentChanges.first!.id
        var group = try #require(core.state.adDomains)
        #expect(group.isBrowsersOnly && group.rules.count == 1)
        #expect(group.rules[0].remote == .domain("taboola.com") && group.rules[0].action == .deny)
        #expect(!core.state.rules.contains { $0.id == chromeDeny.id })
        #expect(core.recentChanges.first?.summary == "Ad Domains: changed 1 server, replacing 1 rule")
        #expect(core.decide(flowID: UUID(), context: flow(safariApp, host: "trc.taboola.com"), resume: { _ in })
            == .deny(Verdict(.deny, .rule(group.rules[0].id))))

        // Allow replaces block; nil hands it back to the lists.
        _ = await core.handle(.decideAdDomains([AdDomainDecision(.domain("taboola.com"), .allow)], removingRules: []), client: app, authorization: nil)
        let allowed = core.recentChanges.first!.id
        group = try #require(core.state.adDomains)
        #expect(group.rules.map(\.action) == [.allow])
        _ = await core.handle(.decideAdDomains([AdDomainDecision(.domain("taboola.com"), nil)], removingRules: []), client: app, authorization: nil)
        #expect(core.state.adDomains?.rules.isEmpty == true)
        #expect(core.recentChanges.first?.summary == "Ad Domains: *.taboola.com follows the lists again")
        let automatic = core.recentChanges.first!.id

        // Undo all three, newest first: back to the block, then to Chrome's own rule.
        for id in [automatic, allowed] { _ = await core.handle(.undoChange(id), client: app, authorization: nil) }
        #expect(core.state.adDomains?.rules.map(\.action) == [.deny])
        _ = await core.handle(.undoChange(blocked), client: app, authorization: nil)
        #expect(core.state.rules.contains { $0.id == chromeDeny.id })
        #expect(core.state.adDomains == nil)
    }

    @Test func onlyServersAndDomains() async {
        let (core, _) = makeCore()
        let reply = await core.handle(.decideAdDomains([AdDomainDecision(.address("1.2.3.4"), .deny)], removingRules: []), client: app, authorization: nil)
        guard case .error(.invalid) = reply else {
            Issue.record("expected an error")
            return
        }
        #expect(core.state.adDomains == nil)
    }

    @Test func savingTheGroupKeepsItsContentsAndScope() async throws {
        let (core, _) = makeCore()
        _ = await core.handle(.decideAdDomains([AdDomainDecision(.host("ads.example.com"), .deny)], removingRules: []), client: app, authorization: nil)
        var group = try #require(core.state.adDomains)
        let stamp = try #require(group.modifiedAt)
        group.isEnabled = false
        group.appliesTo = .allApps
        _ = await core.handle(.saveRuleGroup(group), client: app, authorization: nil)
        let saved = try #require(core.state.adDomains)
        #expect(!saved.isEnabled && saved.appliesTo == .allApps && saved.rules.count == 1)
        #expect((saved.modifiedAt ?? .distantPast) >= stamp)
        // Scope changes are journaled, so they can be undone.
        _ = await core.handle(.undoChange(core.recentChanges.first!.id), client: app, authorization: nil)
        #expect(core.state.adDomains?.isBrowsersOnly == true && core.state.adDomains?.isEnabled == true)

        // A newer copy from another Mac replaces the contents, keeping its date.
        var remote = try #require(core.state.adDomains)
        remote.rules = [Rule(action: .allow, process: .path("/odd"), remote: .domain("example.org"), ports: .single(80))]
        remote.modifiedAt = Date().addingTimeInterval(60)
        _ = await core.handle(.saveRuleGroup(remote), client: app, authorization: nil)
        let synced = try #require(core.state.adDomains)
        #expect(synced.rules.count == 1 && synced.rules[0].process == .any && synced.rules[0].ports == .any)
        #expect(synced.rules[0].origin == .ruleGroup(RuleGroup.adDomainsID))
        #expect(synced.modifiedAt == remote.modifiedAt)
    }

    @Test func classifiesFromListsAndKnownServices() async throws {
        let (core, _) = makeCore()
        _ = await core.handle(.importRuleGroup(name: "Ads", contents: Data("adserver.example\n".utf8), format: .domains),
                              client: app, authorization: nil)
        let info = core.classify(["stats.g.doubleclick.net", "x.adserver.example", "www.apple.com"])
        #expect(info[0].category == .advertising && info[0].source == "Google's DoubleClick")
        #expect(info[1].category == .advertising && info[1].source == "Ads")
        #expect(info[2].category == nil)
    }
}

@Suite struct AntiAdblockTests {
    @Test func servicesIncludeTheirSubdomains() {
        #expect(AntiAdblock.service(for: "html-load.com") == "Ad-Shield")
        #expect(AntiAdblock.service(for: "fb.HTML-LOAD.com") == "Ad-Shield")
        #expect(AntiAdblock.service(for: "x.upapi.net") == "Blockthrough")
        #expect(AntiAdblock.service(for: "html-load.com.example.org") == nil)
        #expect(AntiAdblock.service(for: "loader.com") == nil)
    }

    @Test func classifiedBeforeAnyList() async {
        let (core, _) = makeCore()
        _ = await core.handle(.importRuleGroup(name: "Ads", contents: Data("html-load.cc\n".utf8), format: .domains), client: app, authorization: nil)
        let info = core.classify(["0.html-load.cc"])
        #expect(info[0].category == .antiAdblock && info[0].source == "Ad-Shield")
    }

    @Test func advisorStopsSuggestingABlock() throws {
        var state = FirewallState()
        // The user blocked it for Safari, and HaGeZi lists it: both would lean towards deny.
        state.rules = [Rule(action: .deny, process: .path(safariApp.path), remote: .host("html-load.com"))]
        let pro = ReferenceList(id: "pro", kind: .tracker, name: "HaGeZi Multi Pro", url: URL(string: "https://example.com")!)
        let listed = CompiledBlocklist(domains: DomainSet(suffixes: ["html-load.com"]))
        let advice = try #require(Advisor.advise(Chrome.connection(host: "fb.html-load.com"), state: state,
                                                 references: [(pro, listed)], history: DomainHistory()))
        #expect(advice.suggestion == .allow)
        #expect(!advice.isConfident) // a suggestion, never decided on the user's behalf
        #expect(advice.suggestedDomain == "html-load.com")
        #expect(advice.headline?.contains("Ad-Shield") == true)
        #expect(advice.reasons.contains { $0.kind == .trackerList && $0.leansTo == nil }) // still shown, as information

        // A known threat still wins.
        let threat = ReferenceList(id: "tif", kind: .threat, name: "HaGeZi Threat Intelligence", url: URL(string: "https://example.com")!)
        let bad = try #require(Advisor.advise(Chrome.connection(host: "html-load.com"), state: state, references: [(threat, listed)],
                                              history: DomainHistory()))
        #expect(bad.suggestion == .deny)
    }

    @Test func switchingTheBrowserAdLevel() throws {
        var state = FirewallState()
        #expect(state.browserAdGroup(switchingTo: .off) == nil)
        let light = try #require(state.browserAdGroup(switchingTo: .light))
        #expect(light.isBrowsersOnly && light.isEnabled && light.catalogID == "hagezi-light" && light.name == "HaGeZi Multi Light for Browsers")
        state.ruleGroups = [light]
        #expect(state.browserAdGroup(switchingTo: .light) == nil)
        let pro = try #require(state.browserAdGroup(switchingTo: .pro))
        #expect(pro.id == light.id && pro.catalogID == "hagezi-pro" && pro.url == BrowserAdLevel.pro.catalogEntry?.url)
        let off = try #require(state.browserAdGroup(switchingTo: .off))
        #expect(off.id == light.id && !off.isEnabled)
    }
}

@Suite struct AdDomainsBackupTests {
    @Test func mergingABackupDoesntDuplicateAdDomains() async throws {
        let (core, _) = makeCore()
        _ = await core.handle(.decideAdDomains([AdDomainDecision(.domain("taboola.com"), .deny)], removingRules: []), client: app, authorization: nil)
        guard case .data(let backup) = await core.handle(.exportBackup, client: app, authorization: nil) else {
            Issue.record("no backup")
            return
        }
        _ = await core.handle(.importBackup(backup, merge: true), client: app, authorization: nil)
        #expect(core.state.ruleGroups.filter(\.isAdDomains).count == 1)
    }
}
