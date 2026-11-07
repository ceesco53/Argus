import AppKit
import ArgusKit
import Foundation

// MARK: - Rules for apps' helpers

extension AppModel {
    /// Rules written for helpers inside an app (Chrome's network service, an Electron app's helper)
    /// that would keep working longer as rules for the app itself.
    var helperRuleMove: HelperRuleMove {
        let seen = Set(processes.values.lazy.flatMap(\.viaPaths))
        return RuleAnalysis.movingHelperRules(state.rules, app: { self.appProgram(bundle: $0) }, seenFiledUnderApp: seen)
    }

    /// The app's own program for an app bundle path: as Argus saw it running, or as installed.
    func appProgram(bundle: String) -> ProcessIdentity? {
        if let seen = processes.values.first(where: { $0.identity.isMainProgram(ofApp: bundle) }) { return seen.identity }
        if let cached = installedAppPrograms[bundle] { return cached }
        let identity = Bundle(path: bundle)?.executablePath.map { CodeSignature.identity(path: $0) }
        installedAppPrograms[bundle] = identity
        return identity
    }

    /// Rewrites every helper rule for its app, as one change that can be undone.
    func moveHelperRules() async {
        let move = helperRuleMove
        guard !move.isEmpty else { return }
        let apps = ListFormatter.localizedString(byJoining: move.apps.keys.sorted())
        let summary = "Moved \(move.count) helper rule\(move.count == 1 ? "" : "s") to \(apps)"
        await performUndoable(.changeRules(save: move.moved, delete: move.duplicates, summary: summary))
    }
}

// MARK: - Page Check

extension AppModel {
    /// The app a page check would record: the one at `appPath`, or the app the user was just using.
    func pageCheckTarget(appPath: String?) -> PageCheck.Target? {
        func target(_ identity: ProcessIdentity, name: String? = nil) -> PageCheck.Target {
            PageCheck.Target(path: identity.path, name: name ?? identity.name, bundleIdentifier: identity.bundleIdentifier,
                             bundlePath: identity.appBundlePath ?? ProcessIdentity.outermostAppBundle(for: identity.path),
                             designatedRequirement: identity.designatedRequirement)
        }
        if let appPath {
            return target(processes[appPath]?.identity ?? CodeSignature.identity(path: appPath))
        }
        guard let app = busy.foregroundApp else { return nil }
        let executable = app.executableURL?.resolvingSymlinksInPath().path
        if let executable, let process = processes[executable] { return target(process.identity, name: app.localizedName) }
        if let path = foregroundProcessPath, let process = processes[path], !process.identity.isWebKitNetworking {
            return target(process.identity, name: app.localizedName)
        }
        return executable.map { target(CodeSignature.identity(path: $0), name: app.localizedName) }
    }

    /// Starts recording what the app connects to and, for a browser Argus may script, reloads its page.
    func startPageCheck(appPath: String?) async {
        await endCulpritSearch()
        guard let target = pageCheckTarget(appPath: appPath) else {
            errorMessage = "Choose the app to check first."
            return
        }
        troubleshootAppPath = target.path
        let check = PageCheck(target: target, started: Date(), recordingEnds: Date().addingTimeInterval(PageCheck.recordingTime))
        pageCheck = check
        guard BrowserScripting.canScript(target) else { return }
        let site = await BrowserScripting.frontTabURL(of: target)
        guard pageCheck?.id == check.id else { return }
        pageCheck?.site = site
        await reloadPageCheck()
    }

    /// Records for a while longer and asks the browser to reload (when Argus may).
    func reloadPageCheck() async {
        guard let check = pageCheck else { return }
        pageCheck?.recordingEnds = Date().addingTimeInterval(PageCheck.recordingTime)
        guard BrowserScripting.canScript(check.target) else { return }
        let reloaded = await BrowserScripting.reloadFrontTab(of: check.target)
        if pageCheck?.id == check.id { pageCheck?.reloadedByArgus = reloaded }
    }

    func stopPageCheck() {
        pageCheck?.recordingEnds = Date()
    }

    /// Closes the check. Changes tried from it stay until they run out by themselves.
    func closePageCheck() async {
        await endCulpritSearch()
        pageCheck = nil
    }

    /// Adds the app's new decisions to a running check.
    func recordForPageCheck(_ entries: [FlowLogEntry]) {
        guard let check = pageCheck, check.isRecording || check.search != nil else { return }
        let matching = entries.filter { $0.date >= check.started && belongs($0.processPath, to: check.target) }
        guard !matching.isEmpty else { return }
        pageCheck?.entries.append(contentsOf: matching)
    }

    private func belongs(_ path: String, to target: PageCheck.Target) -> Bool {
        if path == target.path { return true }
        guard let bundle = target.bundlePath else { return false }
        return identity(for: path).appBundlePath == bundle
    }

    /// A rule for the checked app and one server. Temporary ones are high priority, so they take
    /// effect whatever else matches; they run out by themselves.
    func pageCheckRule(_ action: RuleAction, host: String, target: PageCheck.Target, temporary: Bool) -> Rule {
        let remote: RemoteMatch = IPAddress(host) != nil ? .address(host) : .host(host)
        return Rule(action: action, process: .path(target.path), codeRequirement: target.designatedRequirement, remote: remote,
                    isPriority: temporary,
                    expiration: temporary ? .date(Date().addingTimeInterval(TimeInterval(PageCheck.trialMinutes * 60))) : .never,
                    notes: temporary ? "Page Check: trying it for \(PageCheck.trialMinutes) minutes" : "From Page Check")
    }

    /// The temporary rule a check made for a server, while it lasts.
    func pageCheckTrial(_ host: String) -> Rule? {
        guard let id = pageCheck?.trials[host] else { return nil }
        return state.rules.first { $0.id == id }
    }

    /// Lets a server through (or blocks it) for a few minutes, then reloads to show the difference.
    func tryInPageCheck(_ action: RuleAction, host: String) async {
        guard let check = pageCheck else { return }
        let rule = pageCheckRule(action, host: host, target: check.target, temporary: true)
        let previous = check.trials[host].map { [$0] } ?? []
        let verb = action == .allow ? "Letting \(check.target.name) reach" : "Blocking \(check.target.name) from"
        guard await performUndoable(.changeRules(save: [rule], delete: previous,
                                                 summary: "\(verb) \(host) for \(PageCheck.trialMinutes) minutes")) else { return }
        pageCheck?.trials[host] = rule.id
        await reloadPageCheck()
    }

    /// Makes a tried decision permanent for the app, replacing its rules that say the opposite
    /// about the same server (which might otherwise outrank it).
    func keepPageCheckTrial(_ host: String) async {
        guard let check = pageCheck, let trial = pageCheckTrial(host) else { return }
        let (rules, conflicting) = permanentPageCheckRules([(host, trial)], target: check.target)
        let verb = trial.action == .allow ? "allow" : "block"
        guard await performUndoable(.changeRules(save: rules, delete: conflicting, summary: "Always \(verb) \(check.target.name) → \(host)"))
        else { return }
        pageCheck?.trials[host] = nil
    }

    /// Allows (or blocks) a server for the checked app from now on, without trying it first.
    func alwaysInPageCheck(_ action: RuleAction, host: String) async {
        guard let check = pageCheck else { return }
        let draft = pageCheckRule(action, host: host, target: check.target, temporary: true)
        let (rules, conflicting) = permanentPageCheckRules([(host, draft)], target: check.target)
        let verb = action == .allow ? "allow" : "block"
        guard await performUndoable(.changeRules(save: rules, delete: conflicting, summary: "Always \(verb) \(check.target.name) → \(host)"))
        else { return }
        await reloadPageCheck()
    }

    func undoPageCheckTrial(_ host: String) async {
        guard let id = pageCheck?.trials[host] else { return }
        await deleteRules([id])
        pageCheck?.trials[host] = nil
        await reloadPageCheck()
    }

    /// Permanent, normal-priority versions of temporary rules, and the app's rules they replace.
    private func permanentPageCheckRules(_ trials: [(host: String, rule: Rule)], target: PageCheck.Target) -> ([Rule], [UUID]) {
        let programs = Set([target.path] + (processes[target.path]?.viaPaths ?? []))
        var conflicting: [UUID] = []
        let rules = trials.map { host, trial in
            var rule = trial
            rule.expiration = .never
            rule.isPriority = false
            rule.notes = "From Page Check"
            // Only rules for exactly this server: a rule for its whole domain ranks below this one anyway.
            conflicting += state.rules.filter { other in
                guard other.id != trial.id, other.action != trial.action, !other.isPriority,
                      other.process.path.map(programs.contains) == true else { return false }
                switch other.remote {
                case .host(let value), .address(let value): return value.lowercased() == host
                default: return false
                }
            }.map(\.id)
            return rule
        }
        return (rules, conflicting)
    }

    #if DEBUG
    /// A finished check on the demo's activity (`-ArgusDebugPageCheck YES`, or `search` to show a
    /// culprit search under way), for working on its design.
    func showSamplePageCheck(searching: Bool) {
        guard let path = troubleshootAppPath, let target = pageCheckTarget(appPath: path) else { return }
        // The demo loads a page just before launch (see DemoEngine.loadPage).
        let site = DemoEngine.pageCheckSite
        let start = log.last { $0.processPath == path && $0.remote == site }?.date.addingTimeInterval(-1) ?? Date().addingTimeInterval(-120)
        var check = PageCheck(target: target, started: start, recordingEnds: Date())
        check.entries = log.filter { $0.processPath == path && $0.date >= start && $0.date < start.addingTimeInterval(10) }
        check.site = URL(string: "https://\(site)/today")
        if searching { check.search = CulpritSearch(blocked: check.blockedHosts) }
        pageCheck = check
    }
    #endif

    // MARK: Finding the culprit

    func startCulpritSearch() async {
        guard let check = pageCheck else { return }
        // Anti-adblock servers are the usual culprits, so they go in the first half tested.
        let suspects = check.blockedHosts.filter { AntiAdblock.service(for: $0) != nil } + check.blockedHosts.filter { AntiAdblock.service(for: $0) == nil }
        guard let search = CulpritSearch(blocked: suspects) else { return }
        pageCheck?.search = search
        await applyCulpritTest()
    }

    /// The user's answer: did the page work with this test's servers let through?
    func answerCulpritTest(pageWorked: Bool) async {
        guard var search = pageCheck?.search else { return }
        search.record(pageWorked: pageWorked)
        pageCheck?.search = search
        await applyCulpritTest()
    }

    /// Lets exactly the current test's servers through (for a few minutes), and reloads.
    private func applyCulpritTest() async {
        guard let check = pageCheck, let search = check.search else { return }
        let rules = search.testing.map { pageCheckRule(.allow, host: $0, target: check.target, temporary: true) }
        let summary = switch search.outcome {
        case nil: "Page Check test \(search.step): letting \(rules.count) server\(rules.count == 1 ? "" : "s") through"
        case .found: "Page Check found what \(check.target.name) needs: \(search.testing.joined(separator: ", "))"
        case .notArgus: "Page Check: Argus isn't what breaks the page"
        }
        guard await perform(.changeRules(save: rules, delete: check.searchRules, summary: summary)) != nil else { return }
        pageCheck?.searchRules = rules.map(\.id)
        if search.outcome == nil { await reloadPageCheck() }
    }

    /// Stops searching and blocks again whatever the search let through.
    func endCulpritSearch() async {
        guard let check = pageCheck, check.search != nil else { return }
        if !check.searchRules.isEmpty { await perform(.deleteRules(check.searchRules)) }
        pageCheck?.search = nil
        pageCheck?.searchRules = []
    }

    /// Leaves what the search found let through for its remaining minutes, as ordinary tries.
    func finishCulpritSearch() {
        guard let check = pageCheck, let search = check.search else { return }
        for (host, id) in zip(search.testing, check.searchRules) { pageCheck?.trials[host] = id }
        pageCheck?.search = nil
        pageCheck?.searchRules = []
    }

    /// Always allows what the search found, for the checked app.
    func keepCulprits() async {
        guard let check = pageCheck, let search = check.search, case .found(let hosts)? = search.outcome else { return }
        let trials = zip(search.testing, check.searchRules).compactMap { host, id in state.rules.first { $0.id == id }.map { (host, $0) } }
        let (rules, conflicting) = permanentPageCheckRules(trials, target: check.target)
        let summary = "Always allow \(check.target.name) → \(hosts.joined(separator: ", "))"
        guard await performUndoable(.changeRules(save: rules, delete: conflicting, summary: summary)) else { return }
        pageCheck?.search = nil
        pageCheck?.searchRules = []
    }
}

// MARK: - Ads in browsers

/// One ad domain in the Ads screen: what Argus decided about it in browsers, and why.
struct AdDomainRow: Identifiable, Equatable {
    /// What a decision about this row applies to: usually the registrable domain.
    var remote: RemoteMatch
    /// The user's choice in Ad Domains; nil follows the lists.
    var decision: RuleAction?
    /// The most telling classification among its servers (anti-adblock, then threat, then advertising).
    var info: HostInfo?
    var hosts: [String] = []
    var attempts = 0
    var blocked = 0
    var lastSeen: Date?
    var browsers: [String] = []
    /// The most recent decision Argus made about one of its servers.
    var latest: Verdict?

    var id: String { AdDomainRow.key(remote) }
    var name: String { remote.value }
    var isBlockedNow: Bool { latest?.action == .deny }

    static func key(_ remote: RemoteMatch) -> String { "\(remote.kindName)|\(remote.value.lowercased())" }
}

extension AppModel {
    /// Switches "Ads in Browsers" to another of HaGeZi's lists, or off.
    func setBrowserAdLevel(_ level: BrowserAdLevel) async {
        guard let group = state.browserAdGroup(switchingTo: level) else { return }
        guard group.isEnabled else {
            await save(group)
            return
        }
        refreshingGroups.insert(group.id)
        await save(group)
        await perform(.refreshRuleGroups([group.id]))
        refreshingGroups.remove(group.id)
    }

    func decideAdDomains(_ decisions: [AdDomainDecision], replacing rules: [UUID] = []) async {
        guard !decisions.isEmpty || !rules.isEmpty else { return }
        await performUndoable(.decideAdDomains(decisions, removingRules: rules))
    }

    func setAdDomains(enabled: Bool? = nil, appliesTo: AppScope? = nil) async {
        var group = state.adDomains ?? RuleGroup.adDomains()
        if let enabled { group.isEnabled = enabled }
        if let appliesTo { group.appliesTo = appliesTo }
        await save(group)
    }

    /// Asks the engine what kind of servers these are, for the ones not asked about yet.
    func classify(_ hosts: some Sequence<String>) async {
        let wanted = Array(Set(hosts.filter { hostInfo[$0] == nil }))
        guard !wanted.isEmpty, case .hostInfo(let infos)? = await ask(.classifyHosts(wanted)) else { return }
        var updated = hostInfo
        for info in infos { updated[info.host] = info }
        hostInfo = updated
    }

    /// Forgets classifications, after the lists change.
    func reclassify() { hostInfo = [:] }

    /// The browser a program belongs to, by name: Safari, or Google Chrome for one of its helpers.
    func browserName(forProgram path: String) -> String? {
        if let id = processes[path]?.identity.bundleIdentifier, let browser = Browsers.browser(bundleIdentifier: id) { return browser.name }
        guard let bundle = ProcessIdentity.outermostAppBundle(for: path) else { return nil }
        return Browsers.browser(bundleIdentifier: Bundle(path: bundle)?.bundleIdentifier)?.name
    }

    /// Every server browsers reached (or tried to), grouped by domain, with Ad Domains' choices.
    func adDomainRows() -> [AdDomainRow] {
        let decisions = state.adDomains?.rules ?? []
        var rows: [String: AdDomainRow] = [:]
        for rule in decisions {
            rows[AdDomainRow.key(rule.remote)] = AdDomainRow(remote: rule.remote, decision: rule.action)
        }
        // The decision that covers a host: its own, else the deepest domain containing it.
        let hostDecisions = Set(decisions.compactMap { if case .host(let h) = $0.remote { h } else { nil } })
        let domainDecisions = decisions.compactMap { if case .domain(let d) = $0.remote { d } else { nil } }.sorted { $0.count > $1.count }
        func remote(for host: String) -> RemoteMatch {
            if hostDecisions.contains(host) { return .host(host) }
            if let domain = domainDecisions.first(where: { host == $0 || host.hasSuffix("." + $0) }) { return .domain(domain) }
            return .domain(DomainName.registrableDomain(of: host) ?? host)
        }

        var browserNames: [String: String?] = [:]
        for connection in connections.values where connection.direction == .outgoing {
            guard let host = connection.hostname else { continue }
            let name = browserNames[connection.processPath] ?? browserName(forProgram: connection.processPath)
            browserNames[connection.processPath] = name
            guard let browser = name else { continue }
            let target = remote(for: host)
            var row = rows[AdDomainRow.key(target)] ?? AdDomainRow(remote: target)
            if !row.hosts.contains(host) { row.hosts.append(host) }
            if !row.browsers.contains(browser) { row.browsers.append(browser) }
            row.attempts += connection.connectCount
            row.blocked += connection.denyCount
            if (row.lastSeen ?? .distantPast) < connection.lastSeen {
                row.lastSeen = connection.lastSeen
                row.latest = connection.lastVerdict
            }
            rows[AdDomainRow.key(target)] = row
        }
        return rows.values.map { row in
            var row = row
            let candidates = (row.hosts + [row.remote.value]).compactMap { hostInfo[$0] }.filter { $0.category != nil }
            let rank: [HostCategory: Int] = [.antiAdblock: 0, .threat: 1, .advertising: 2]
            row.info = candidates.min { rank[$0.category!]! < rank[$1.category!]! }
            return row
        }
    }

    /// Hosts and decided servers the Ads screen should have classified.
    func adDomainHostsToClassify() -> [String] {
        var hosts = Set((state.adDomains?.rules ?? []).map(\.remote.value))
        var browserPaths: [String: Bool] = [:]
        for connection in connections.values {
            guard let host = connection.hostname else { continue }
            let isBrowser = browserPaths[connection.processPath] ?? (browserName(forProgram: connection.processPath) != nil)
            browserPaths[connection.processPath] = isBrowser
            if isBrowser { hosts.insert(host) }
        }
        return Array(hosts)
    }

    /// The user's deny rules for one browser that block a server or domain: candidates for Ad
    /// Domains, which blocks in every browser.
    var browserRulesForAdDomains: [Rule] {
        state.rules.filter { rule in
            guard rule.action == .deny, rule.isEnabled, !rule.isPriority, rule.expiration == .never, rule.direction != .incoming,
                  rule.profileID == nil, let path = rule.process.path else { return false }
            switch rule.remote {
            case .host, .domain: return browserName(forProgram: path) != nil
            default: return false
            }
        }
    }
}
