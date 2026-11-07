import ArgusKit
import SwiftUI

/// Troubleshoot's "check a page": record what a browser connects to while a page reloads, see what
/// was blocked and why, and try letting things through for a few minutes.
struct PageCheckCard: View {
    @Environment(AppModel.self) private var model
    let appPath: String?
    @State private var showAllowed = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let check = model.pageCheck, check.target.path == appPath {
                running(check)
            } else {
                intro
            }
        }
        .card()
    }

    // MARK: Before a check

    private var intro: some View {
        let target = model.pageCheckTarget(appPath: appPath)
        let name = target?.name ?? "the app"
        let isBrowser = target?.isBrowser ?? false
        let scriptable = target.map(BrowserScripting.canScript) ?? false
        return VStack(alignment: .leading, spacing: 10) {
            Text(isBrowser ? "Check a page" : "Watch what \(name) connects to").font(.headline)
            Text(isBrowser
                 ? "Argus records everything \(name) connects to while the page reloads: what was blocked, and by which list or rule. Then let things through for \(PageCheck.trialMinutes) minutes to see what fixes it, or let Argus find out."
                 : "Argus records everything \(name) connects to for a few seconds: what was blocked, and by which list or rule.")
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Button(isBrowser ? (scriptable ? "Reload and Check" : "Check Page") : "Start Recording") {
                    Task { await model.startPageCheck(appPath: appPath) }
                }
                .buttonStyle(.borderedProminent)
                .disabled(target == nil)
                if isBrowser {
                    Text(scriptable ? "macOS may ask you once to let Argus control \(name)." : "Then reload the page in \(name).")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    // MARK: During and after

    private func running(_ check: PageCheck) -> some View {
        let rows = check.rows
        let blocked = rows.filter { $0.wasBlocked || model.pageCheckTrial($0.host) != nil }
        let allowed = rows.filter { !($0.wasBlocked || model.pageCheckTrial($0.host) != nil) }
        return VStack(alignment: .leading, spacing: 12) {
            status(check, rows: rows)
            if check.search != nil { CulpritSearchPanel(check: check) }
            if rows.isEmpty {
                Text("Nothing yet.").foregroundStyle(.tertiary)
            }
            if !blocked.isEmpty {
                Text("Blocked (\(blocked.count))").font(.subheadline.weight(.semibold))
                VStack(spacing: 6) {
                    ForEach(blocked) { PageCheckRowView(row: $0, check: check) }
                }
            }
            if !allowed.isEmpty {
                DisclosureGroup(isExpanded: $showAllowed) {
                    VStack(spacing: 6) {
                        ForEach(allowed) { PageCheckRowView(row: $0, check: check) }
                    }
                    .padding(.top, 6)
                } label: {
                    Text("Allowed (\(allowed.count))").font(.subheadline.weight(.semibold))
                }
            }
            HStack {
                if check.search == nil, !check.blockedHosts.isEmpty {
                    Button("Find What the Page Needs") { Task { await model.startCulpritSearch() } }
                        .help("Lets half of what was blocked through at a time and asks whether the page works, until it finds the culprit")
                }
                Spacer()
                Button("Done") { Task { await model.closePageCheck() } }
            }
        }
        .task(id: rows.count) { await model.classify(rows.map(\.host)) }
    }

    private func status(_ check: PageCheck, rows: [PageCheck.Row]) -> some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                if context.date < check.recordingEnds {
                    ProgressView().controlSize(.small)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Recording what \(check.target.name) connects to… \(Int(check.recordingEnds.timeIntervalSince(context.date).rounded()))s")
                            .font(.headline)
                        Text(check.reloadedByArgus ? "Argus reloaded the page." : "Reload the page in \(check.target.name) now.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("Stop") { model.stopPageCheck() }
                } else {
                    Image(systemName: "doc.text.magnifyingglass").font(.title3).foregroundStyle(.tint)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(summary(check, rows: rows)).font(.headline)
                        if let host = check.site?.host() {
                            Text("Page: \(host)").font(.callout).foregroundStyle(.secondary)
                        }
                    }
                    Spacer()
                    Button(BrowserScripting.canScript(check.target) ? "Reload and Check Again" : "Check Again") {
                        Task { await model.reloadPageCheck() }
                    }
                }
            }
        }
    }

    private func summary(_ check: PageCheck, rows: [PageCheck.Row]) -> String {
        let blocked = rows.filter { $0.latest.action == .deny }.count
        guard !rows.isEmpty else { return "\(check.target.name) didn't connect anywhere new" }
        let servers = "\(rows.count) server\(rows.count == 1 ? "" : "s")"
        return blocked == 0 ? "\(check.target.name) reached \(servers); nothing was blocked"
            : "\(check.target.name) reached \(servers); \(blocked) blocked"
    }
}

/// One server in a page check, with what Argus did and quick ways to change it.
private struct PageCheckRowView: View {
    @Environment(AppModel.self) private var model
    let row: PageCheck.Row
    let check: PageCheck

    var body: some View {
        let trial = model.pageCheckTrial(row.host)
        let testing = check.searchRuleHosts.contains(row.host)
        let blockedNow = row.latest.action == .deny && trial == nil && !testing
        HStack(spacing: 10) {
            Image(systemName: blockedNow ? "xmark.octagon.fill" : row.wasBlocked ? "arrow.uturn.forward.circle.fill" : "checkmark.circle.fill")
                .foregroundStyle(blockedNow ? Color.denied : row.wasBlocked ? Color.orange : Color.allowed)
                .accessibilityLabel(blockedNow ? "Blocked" : "Allowed")
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 6) {
                    Text(row.host).lineLimit(1).truncationMode(.middle)
                    if row.isSite { Pill(text: "This site", tint: .secondary) }
                    if let info = model.hostInfo[row.host] { HostCategoryPill(info: info) }
                }
                Text(detail(trial: trial, testing: testing))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .help(detail(trial: trial, testing: testing))
            }
            Spacer(minLength: 6)
            if row.attempts > 1 {
                Text("×\(row.attempts)").font(.caption).foregroundStyle(.tertiary).help("\(row.attempts) attempts")
            }
            actions(trial: trial, testing: testing, blockedNow: blockedNow)
                .controlSize(.small)
                .fixedSize()
        }
        .padding(.vertical, 2)
    }

    private func detail(trial: Rule?, testing: Bool) -> String {
        let was = row.firstDenial.map { " · was blocked by \(reason($0))" } ?? ""
        if testing { return "Let through for this test" + was }
        if let trial {
            let until = if case .date(let end) = trial.expiration { " until \(end.formatted(date: .omitted, time: .shortened))" } else { "" }
            return (trial.action == .allow ? "Let through" : "Blocked") + until + was
        }
        return reason(row.latest)
    }

    private func reason(_ verdict: Verdict) -> String {
        let text = verdict.reason.explanation(in: model.state)
        return text.hasPrefix("Rule: ") || text.hasPrefix("Blocklist: ") ? String(text.drop { $0 != " " }.dropFirst()) : text
    }

    @ViewBuilder
    private func actions(trial: Rule?, testing: Bool, blockedNow: Bool) -> some View {
        let name = check.target.name
        if testing {
            EmptyView()
        } else if trial != nil {
            HStack(spacing: 6) {
                Button("Keep") { Task { await model.keepPageCheckTrial(row.host) } }
                    .help("Make this permanent for \(name)")
                Button("Undo") { Task { await model.undoPageCheckTrial(row.host) } }
            }
        } else {
            let action: RuleAction = blockedNow ? .allow : .deny
            HStack(spacing: 6) {
                Button(blockedNow ? "Allow \(PageCheck.trialMinutes) min" : "Block \(PageCheck.trialMinutes) min") {
                    Task { await model.tryInPageCheck(action, host: row.host) }
                }
                .help(blockedNow ? "Let \(name) reach \(row.host) for \(PageCheck.trialMinutes) minutes, then reload"
                                 : "Block \(name) from \(row.host) for \(PageCheck.trialMinutes) minutes, then reload")
                Menu {
                    Button(blockedNow ? "Always Allow for \(name)" : "Always Block for \(name)") {
                        Task { await model.alwaysInPageCheck(action, host: row.host) }
                    }
                    if check.target.isBrowser, IPAddress(row.host) == nil {
                        // Allow just this server; block the whole ad domain.
                        let remote: RemoteMatch = blockedNow ? .host(row.host) : .domain(DomainName.registrableDomain(of: row.host) ?? row.host)
                        Button(blockedNow ? "Allow \(row.host) in All Browsers" : "Block \(remote.value) in All Browsers") {
                            Task {
                                await model.decideAdDomains([AdDomainDecision(remote, action)])
                                await model.reloadPageCheck()
                            }
                        }
                    }
                    if blockedNow, case .rule(let id) = row.latest.reason, let rule = model.state.rules.first(where: { $0.id == id }) {
                        Divider()
                        Button("Delete Rule: \(rule.summary)") { Task { await model.deleteRules([id]) } }
                    }
                } label: {
                    Image(systemName: "ellipsis")
                }
                .menuStyle(.borderlessButton)
                .menuIndicator(.hidden)
            }
        }
    }
}

/// Step-by-step: let half of the suspects through, reload, ask whether the page works.
private struct CulpritSearchPanel: View {
    @Environment(AppModel.self) private var model
    let check: PageCheck

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let search = check.search {
                switch search.outcome {
                case nil: testing(search)
                case .found(let hosts): found(hosts)
                case .notArgus: notArgus
                }
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.accentColor.opacity(0.09), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
    }

    private func testing(_ search: CulpritSearch) -> some View {
        let name = check.target.name
        let count = search.testing.count
        return VStack(alignment: .leading, spacing: 8) {
            Text(search.step == 1 ? "Test 1: letting everything Argus blocked through" : "Test \(search.step): letting \(count) of \(search.suspects.count) suspects through")
                .font(.headline)
            Text(search.testing.joined(separator: ", "))
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(3)
            Text(check.reloadedByArgus ? "Argus reloaded the page. Does it work now?" : "Reload the page in \(name). Does it work now?")
            HStack {
                Button("It Works") { Task { await model.answerCulpritTest(pageWorked: true) } }
                    .buttonStyle(.borderedProminent)
                Button("Still Broken") { Task { await model.answerCulpritTest(pageWorked: false) } }
                if BrowserScripting.canScript(check.target) {
                    Button("Reload Again") { Task { await model.reloadPageCheck() } }
                }
                Spacer()
                Button("Stop") { Task { await model.endCulpritSearch() } }
                    .help("Block again what this test let through")
            }
            .controlSize(.small)
        }
    }

    private func found(_ hosts: [String]) -> some View {
        let name = check.target.name
        let them = hosts.count == 1 ? "it" : "them"
        return VStack(alignment: .leading, spacing: 8) {
            Label(hosts.count == 1 ? "Found it: the page needs \(hosts[0])" : "The page needs \(hosts.count) of the servers Argus blocked",
                  systemImage: "checkmark.seal.fill")
                .font(.headline)
                .foregroundStyle(Color.allowed)
            if hosts.count > 1 {
                Text(hosts.joined(separator: ", ")).font(.caption).foregroundStyle(.secondary).lineLimit(3)
            }
            Text("Argus is letting \(them) through for \(PageCheck.trialMinutes) minutes.")
                .foregroundStyle(.secondary)
            HStack {
                Button("Always Allow for \(name)") { Task { await model.keepCulprits() } }
                    .buttonStyle(.borderedProminent)
                Button("Leave for \(PageCheck.trialMinutes) Minutes") { model.finishCulpritSearch() }
                Button("Block Again") { Task { await model.endCulpritSearch() } }
            }
            .controlSize(.small)
        }
    }

    private var notArgus: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Argus isn't what breaks this page", systemImage: "info.circle.fill").font(.headline)
            Text("Even with everything Argus blocked let through, the page still didn't work, so the problem is probably elsewhere. Pause protection for a few minutes to be sure.")
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                PauseMenu { Label("Pause Protection…", systemImage: "pause.circle") }
                    .fixedSize()
                Button("Done") { Task { await model.endCulpritSearch() } }
            }
            .controlSize(.small)
        }
    }
}
