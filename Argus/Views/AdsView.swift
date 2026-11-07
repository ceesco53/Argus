import ArgusKit
import SwiftUI

/// Ads in browsers: how much the list blocks, and the user's own choices about ad domains, with
/// what browsers actually reached so too many ads, or a broken site, is a click away from fixed.
struct AdsView: View {
    @Environment(AppModel.self) private var model
    @State private var rows: [AdDomainRow] = []
    @State private var filter: Filter = .relevant
    @State private var search = ""
    @State private var newDomain = ""
    @State private var showMove = false
    /// Rules for one browser that could move to Ad Domains, and those browsers' names. Worked out
    /// with the rows rather than on every redraw, which would follow activity every second.
    @State private var moveCandidates: (count: Int, browsers: [String]) = (0, [])
    @AppStorage("browserRuleMoveDismissed") private var moveDismissed = 0

    enum Filter: String, CaseIterable, Identifiable {
        case relevant = "Ads, Trackers and Anything Blocked"
        case blocked = "Blocked Now"
        case gotThrough = "Ads That Got Through"
        case yours = "Your Choices"
        case everything = "Everything Browsers Reached"
        var id: String { rawValue }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                intro
                if model.engine == .monitor { MonitorModeBanner(compact: true) }
                levelCard
                adDomainsCard
            }
            .padding(24)
        }
        .navigationTitle("Ads in Browsers")
        .searchable(text: $search, placement: .toolbar, prompt: "Domains")
        .task {
            // Quickly at first, while Argus may still be loading its activity, then every few seconds.
            var round = 0
            while !Task.isCancelled {
                await model.classify(model.adDomainHostsToClassify())
                refresh()
                round += 1
                try? await Task.sleep(for: .seconds(round < 8 ? 1 : 5))
            }
        }
        .onChange(of: model.state.revision) { refresh() }
        .onChange(of: model.state.browserAdGroup?.lastUpdated) {
            model.reclassify()
            Task { await model.classify(model.adDomainHostsToClassify()) }
        }
        .onChange(of: model.hostInfo.count) { rows = model.adDomainRows() }
        .sheet(isPresented: $showMove, onDismiss: refresh) { MoveBrowserRulesSheet().environment(model) }
    }

    private func refresh() {
        rows = model.adDomainRows()
        let candidates = model.browserRulesForAdDomains
        moveCandidates = (candidates.count, Set(candidates.compactMap { $0.process.path.flatMap(model.browserName(forProgram:)) }).sorted())
    }

    private var intro: some View {
        HStack(alignment: .top, spacing: 16) {
            Image(systemName: "rectangle.badge.xmark").font(.system(size: 34)).foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 4) {
                Text("Ads in browsers").font(.title2.weight(.semibold))
                Text("Block ad and tracking servers in Safari, Chrome and other browsers without touching your other apps. If a site breaks or says you're blocking ads, check the page in Troubleshoot to see what to let through.")
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    // MARK: The list

    private var levelCard: some View {
        let level = model.state.browserAdLevel
        let group = model.state.browserAdGroup
        return VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("How much to block").font(.headline)
                Spacer()
                if let group, model.refreshingGroups.contains(group.id) { ProgressView().controlSize(.small) }
            }
            Picker("How much to block", selection: Binding(
                get: { level },
                set: { newLevel in Task { await model.setBrowserAdLevel(newLevel) } })) {
                ForEach(BrowserAdLevel.allCases, id: \.self) { Text($0.displayName).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()
            Text(level.explanation).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            let everyApp = model.state.ruleGroups.filter { group in
                group.isEnabled && !group.isBrowsersOnly && group.url != nil && group.domainCount + group.hostCount > 0
                    && BlocklistCatalog.entry(id: group.catalogID)?.category != .security
            }
            if !everyApp.isEmpty {
                Button("Your blocklists for every app (\(ListFormatter.localizedString(byJoining: everyApp.map(\.name)))) block in browsers too.") {
                    model.section = .blocklists
                }
                .buttonStyle(.link)
                .font(.caption)
            }
            if let group, group.isEnabled {
                HStack(spacing: 6) {
                    Text(group.name)
                    Text("·")
                    Text(group.entryCount > 0 ? "\(group.entryCount.formatted()) entries" : "Downloading…")
                    if let updated = group.lastUpdated { Text("· updated \(updated.relative)") }
                }
                .font(.caption)
                .foregroundStyle(.secondary)
                if let error = group.lastError {
                    Label(error, systemImage: "exclamationmark.triangle.fill").font(.caption).foregroundStyle(.orange)
                }
            }
        }
        .card()
    }

    // MARK: Ad Domains

    private var adDomainsCard: some View {
        let group = model.state.adDomains
        let shown = visibleRows
        return VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Your ad domains").font(.headline)
                    Text("Block what the list misses and allow what it breaks. Auto leaves a domain to the list. Switch them all off to see whether one of your choices is what breaks a site.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 16)
                Picker("Applies to", selection: Binding(
                    get: { group?.appliesTo ?? .browsers },
                    set: { scope in Task { await model.setAdDomains(appliesTo: scope) } })) {
                    ForEach(AppScope.allCases, id: \.self) { Text($0.displayName).tag($0) }
                }
                .labelsHidden()
                .fixedSize()
                .help("Which apps your ad domain choices apply to")
                Toggle("Your ad domains", isOn: Binding(
                    get: { group?.isEnabled ?? true },
                    set: { value in Task { await model.setAdDomains(enabled: value) } }))
                    .toggleStyle(.switch)
                    .labelsHidden()
                    .help("Turn all your ad domain choices on or off at once")
            }
            if moveCandidates.count > moveDismissed {
                moveBanner
            }
            addField
            HStack {
                Picker("Show", selection: $filter) {
                    ForEach(Filter.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.menu)
                .fixedSize()
                Spacer()
                Text(counts).font(.caption).foregroundStyle(.secondary)
            }
            if shown.isEmpty {
                Text(rows.isEmpty ? "Nothing yet. Browse for a while and the ad and tracking servers your browsers reach show up here."
                                  : "Nothing matches.")
                    .foregroundStyle(.tertiary)
                    .padding(.vertical, 6)
            } else {
                LazyVStack(spacing: 0) {
                    ForEach(shown) { row in
                        AdDomainRowView(row: row)
                        if row.id != shown.last?.id { Divider() }
                    }
                }
            }
        }
        .card()
    }

    private var moveBanner: some View {
        let (count, browsers) = moveCandidates
        return HStack(alignment: .top, spacing: 12) {
            Image(systemName: "arrow.triangle.merge").font(.title3).foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 6) {
                Text("\(count) of your rules block servers in \(ListFormatter.localizedString(byJoining: browsers)) only")
                    .font(.callout.weight(.semibold))
                Text("Move the ad servers here to block them in every browser, and clear out the ones that break sites.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                HStack {
                    Button("Review…") { showMove = true }.buttonStyle(.borderedProminent)
                    Button("Not Now") { moveDismissed = count }
                }
                .controlSize(.small)
            }
            Spacer(minLength: 0)
        }
        .padding(12)
        .background(Color.accentColor.opacity(0.09), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
    }

    private var addField: some View {
        HStack {
            TextField("Add a domain", text: $newDomain, prompt: Text("Add a domain, like ads.example.com"))
                .textFieldStyle(.roundedBorder)
                .onSubmit { add(.deny) }
            Button("Block") { add(.deny) }
            Button("Allow") { add(.allow) }
        }
        .disabled(cleanDomain == nil)
    }

    private var cleanDomain: String? {
        var text = newDomain.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if let url = URL(string: text), let host = url.host() { text = host } // accept pasted addresses
        return DomainSet.normalize(text)
    }

    private func add(_ action: RuleAction) {
        guard let domain = cleanDomain else { return }
        newDomain = ""
        Task { await model.decideAdDomains([AdDomainDecision(.domain(domain), action)]) }
    }

    private var visibleRows: [AdDomainRow] {
        let term = search.trimmingCharacters(in: .whitespaces).lowercased()
        return rows.filter { row in
            switch filter {
            case .relevant: row.decision != nil || row.info?.category != nil || row.blocked > 0
            case .blocked: row.isBlockedNow
            case .gotThrough: row.info?.category == .advertising && row.latest != nil && !row.isBlockedNow
            case .yours: row.decision != nil
            case .everything: true
            }
        }.filter { row in
            term.isEmpty || row.name.contains(term) || row.hosts.contains { $0.contains(term) }
        }.sorted { a, b in
            (a.lastSeen ?? .distantPast, b.name) > (b.lastSeen ?? .distantPast, a.name)
        }
    }

    private var counts: String {
        let blocked = rows.filter(\.isBlockedNow).count
        let through = rows.filter { $0.info?.category == .advertising && $0.latest != nil && !$0.isBlockedNow }.count
        return "\(blocked) blocked · \(through) ad domain\(through == 1 ? "" : "s") got through"
    }
}

/// One domain: what happened to it in browsers, what kind of server it is, and Block / Allow / Auto.
private struct AdDomainRowView: View {
    @Environment(AppModel.self) private var model
    let row: AdDomainRow

    private enum Choice: Hashable { case block, allow, auto }

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: row.latest == nil ? "circle.dashed" : row.isBlockedNow ? "xmark.octagon.fill" : "checkmark.circle.fill")
                .foregroundStyle(row.latest == nil ? Color.secondary : row.isBlockedNow ? Color.denied : Color.allowed)
                .accessibilityLabel(row.latest == nil ? "Not seen yet" : row.isBlockedNow ? "Blocked" : "Allowed")
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(row.name).lineLimit(1).truncationMode(.middle)
                    if case .host = row.remote {
                        Text("this server only").font(.caption2).foregroundStyle(.tertiary)
                    }
                    if let info = row.info { HostCategoryPill(info: info) }
                }
                Text(detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .help(detail)
            }
            Spacer(minLength: 8)
            if row.attempts > 0 {
                Text(row.attempts.formatted())
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.tertiary)
                    .help("\(row.attempts.formatted()) connections, \(row.blocked.formatted()) blocked")
            }
            Picker("Decision for \(row.name)", selection: Binding(
                get: { row.decision == .deny ? Choice.block : row.decision == .allow ? .allow : .auto },
                set: { choice in
                    let action: RuleAction? = switch choice {
                    case .block: .deny
                    case .allow: .allow
                    case .auto: nil
                    }
                    Task { await model.decideAdDomains([AdDomainDecision(row.remote, action)]) }
                })) {
                Text("Block").tag(Choice.block)
                Text("Allow").tag(Choice.allow)
                Text("Auto").tag(Choice.auto)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(width: 180)
            .help("Block or allow \(row.name) and its subdomains in browsers. Auto leaves it to the list.")
        }
        .padding(.vertical, 6)
    }

    private var detail: String {
        guard let latest = row.latest else { return row.decision == nil ? "" : "Not seen in a browser yet" }
        let what = latest.action == .deny ? "Blocked" : "Allowed"
        var reason = latest.reason.explanation(in: model.state)
        for prefix in ["Rule: ", "Blocklist: "] where reason.hasPrefix(prefix) { reason.removeFirst(prefix.count) }
        var parts = ["\(what): \(reason)"]
        parts.append(ListFormatter.localizedString(byJoining: row.browsers))
        if let seen = row.lastSeen { parts.append(seen.relative) }
        if row.hosts.count > 1 { parts.append("\(row.hosts.count) servers") }
        return parts.joined(separator: " · ")
    }
}

/// "Ads & tracking", "Anti-adblock" or "Threat", with who says so.
struct HostCategoryPill: View {
    let info: HostInfo

    var body: some View {
        switch info.category {
        case .advertising?:
            Pill(text: "Ads & tracking", tint: .secondary)
                .help(info.source.map { "Listed by \($0)" } ?? "An advertising or tracking server")
        case .antiAdblock?:
            Pill(text: "Anti-adblock", symbol: "exclamationmark.triangle.fill", tint: .orange)
                .help("\(info.source.map { "Run by \($0), an" } ?? "An") anti-adblock service. Blocking it can make sites refuse to load.")
        case .threat?:
            Pill(text: "Threat", symbol: "exclamationmark.shield.fill", tint: .denied)
                .help(info.source.map { "Listed by \($0) as malware, phishing or scam infrastructure" } ?? "Malware, phishing or scam infrastructure")
        case nil:
            EmptyView()
        }
    }
}

/// Moves rules that block a server in one browser into Ad Domains (every browser), keeps them,
/// or deletes them, one rule at a time with a sensible default.
private struct MoveBrowserRulesSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var choices: [UUID: Choice] = [:]

    enum Choice: Hashable { case move, keep, delete }

    var body: some View {
        let rules = model.browserRulesForAdDomains.sorted { $0.remote.value < $1.remote.value }
        let moving = rules.filter { choice($0) == .move }
        let deleting = rules.filter { choice($0) == .delete }
        VStack(alignment: .leading, spacing: 14) {
            Text("Move rules into Ad Domains").font(.title2.weight(.semibold))
            Text("Each of these rules blocks a server in one browser. Moved to Ad Domains, it blocks it in every browser. Anti-adblock servers are best deleted: blocking them is what makes some sites refuse to load.")
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            List(rules) { rule in
                HStack(spacing: 10) {
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 6) {
                            Text(rule.remote.displayString).lineLimit(1).truncationMode(.middle)
                            if let info = model.hostInfo[rule.remote.value] { HostCategoryPill(info: info) }
                        }
                        Text(rule.process.path.flatMap(model.browserName(forProgram:)) ?? "")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Picker("What to do with \(rule.remote.displayString)", selection: Binding(
                        get: { choice(rule) }, set: { choices[rule.id] = $0 })) {
                        Text("Move").tag(Choice.move)
                        Text("Keep").tag(Choice.keep)
                        Text("Delete").tag(Choice.delete)
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    .frame(width: 200)
                }
            }
            .frame(minHeight: 320)
            HStack {
                Text("Move \(moving.count), delete \(deleting.count), keep \(rules.count - moving.count - deleting.count)")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Apply") {
                    let decisions = moving.map { AdDomainDecision($0.remote, .deny) }
                    let removing = (moving + deleting).map(\.id)
                    Task { await model.decideAdDomains(decisions, replacing: removing) }
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(moving.isEmpty && deleting.isEmpty)
            }
        }
        .padding(24)
        .frame(width: 660, height: 580)
        .task { await model.classify(model.browserRulesForAdDomains.map(\.remote.value)) }
    }

    /// Ads and threats move; anti-adblock servers go; anything else stays as it is.
    private func choice(_ rule: Rule) -> Choice {
        if let chosen = choices[rule.id] { return chosen }
        switch model.hostInfo[rule.remote.value]?.category {
        case .advertising?, .threat?: return .move
        case .antiAdblock?: return .delete
        case nil: return .keep
        }
    }
}
