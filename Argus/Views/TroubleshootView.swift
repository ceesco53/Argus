import AppKit
import ArgusKit
import SwiftUI

/// "Something isn't working": what Argus did to an app, a what-if test, and one-click fixes.
struct TroubleshootView: View {
    @Environment(AppModel.self) private var model
    @State private var host = ""
    @State private var result: ConnectionTestResult?
    @State private var testing = false

    var body: some View {
        @Bindable var model = model
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                HStack(alignment: .top, spacing: 16) {
                    Image(systemName: "stethoscope").font(.system(size: 34)).foregroundStyle(.tint)
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Something not working?").font(.title2.weight(.semibold))
                        Text("Pick the app that's misbehaving. Argus shows what it blocked and why, and can check what it would do with any website.")
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                healthCard
                appCard
                testCard
                if let path = model.troubleshootAppPath { blockedCard(path) }
            }
            .padding(24)
        }
        .navigationTitle("Troubleshoot")
        .onAppear { if model.troubleshootAppPath == nil { model.troubleshootAppPath = model.foregroundProcessPath } }
        .onChange(of: model.troubleshootAppPath) { result = nil }
    }

    private var healthCard: some View {
        HStack(spacing: 12) {
            let status = model.health.status
            Image(systemName: status.isProblem ? "exclamationmark.triangle.fill" : status == .healthy ? "checkmark.circle.fill" : "circle.dotted")
                .font(.title2)
                .foregroundStyle(status.isProblem ? Color.orange : status == .healthy ? Color.allowed : .secondary)
            VStack(alignment: .leading, spacing: 2) {
                Text(status == .healthy ? "The internet is working" : status == .checking ? "Checking…" : status.isProblem ? "There's a connection problem" : "Not checked yet")
                    .font(.headline)
                if let checked = model.health.checkedAt {
                    Text("Checked \(checked.relative)").font(.caption).foregroundStyle(.secondary)
                }
            }
            Spacer()
            Button("Check Again") { Task { await model.checkHealth() } }
                .disabled(status == .checking)
        }
        .card()
    }

    private var appCard: some View {
        @Bindable var model = model
        let apps = model.processes.values.sorted { $0.lastSeen > $1.lastSeen }
        return VStack(alignment: .leading, spacing: 10) {
            Text("Which app?").font(.headline)
            HStack {
                if let path = model.troubleshootAppPath {
                    AppIconView(identity: model.identity(for: path), size: 28)
                }
                Picker("App", selection: $model.troubleshootAppPath) {
                    Text("Choose an app").tag(String?.none)
                    ForEach(apps) { process in
                        Text(process.identity.name).tag(String?.some(process.id))
                    }
                }
                .labelsHidden()
                .frame(maxWidth: 320)
                if let foreground = model.foregroundProcessPath, foreground != model.troubleshootAppPath {
                    // Name the app, not the helper carrying its traffic (Safari, not WebKit.Networking).
                    Button("Use \(model.busy.foregroundApp?.localizedName ?? model.identity(for: foreground).name)") { model.troubleshootAppPath = foreground }
                        .buttonStyle(.link)
                }
            }
        }
        .card()
    }

    private var testCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Check a website or server").font(.headline)
            HStack {
                TextField("Website or server", text: $host, prompt: Text("news.google.com"))
                    .textFieldStyle(.roundedBorder)
                    .onSubmit { Task { await runTest() } }
                Button("Check") { Task { await runTest() } }
                    .buttonStyle(.borderedProminent)
                    .disabled(cleanHost.isEmpty || testing)
            }
            if let result {
                TestResultView(result: result, host: cleanHost, appPath: model.troubleshootAppPath)
            }
        }
        .card()
    }

    private func blockedCard(_ path: String) -> some View {
        let identity = model.identity(for: path)
        let blocked = model.recentlyBlocked.filter { $0.processPath == path }
        return VStack(alignment: .leading, spacing: 10) {
            Text("What Argus blocked for \(identity.name)").font(.headline)
            if blocked.isEmpty {
                Text("Nothing recently. If \(identity.name) still isn't working, the problem is probably elsewhere. Pause protection for a few minutes to be sure.")
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                PauseMenu { Label("Pause Protection…", systemImage: "pause.circle") }
                    .fixedSize()
            } else {
                ForEach(blocked.prefix(20)) { entry in
                    BlockedRow(entry: entry, model: model)
                }
                if blocked.count > 1 {
                    Button("Allow All \(blocked.count) for \(identity.name)") {
                        Task { await model.allow(blocked, forAllApps: false) }
                    }
                }
            }
        }
        .card()
    }

    private var cleanHost: String {
        var text = host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if let url = URL(string: text), let urlHost = url.host { text = urlHost } // accept pasted URLs
        return text
    }

    private func runTest() async {
        guard !cleanHost.isEmpty else { return }
        testing = true
        result = await model.test(ConnectionTest(processPath: model.troubleshootAppPath, host: cleanHost))
        testing = false
    }
}

private struct TestResultView: View {
    @Environment(AppModel.self) private var model
    let result: ConnectionTestResult
    let host: String
    let appPath: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                if let verdict = result.verdict {
                    VerdictBadge(verdict: verdict)
                } else {
                    Pill(text: "Would ask", symbol: "bell.badge", tint: .orange)
                }
                Text(result.explanation).font(.callout)
            }
            if let advice = result.advice, let suggestion = advice.suggestion, let headline = advice.headline {
                Label("Argus's suggestion: \(suggestion == .allow ? "allow" : "deny"). \(headline)",
                      systemImage: suggestion == .allow ? "hand.thumbsup" : "hand.raised")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            if result.verdict?.action == .deny || result.verdict == nil {
                HStack {
                    if let appPath {
                        Button("Allow \(result.processName) to Reach \(host)") { Task { await allow(appPath) } }
                            .buttonStyle(.borderedProminent)
                    }
                    Button("Allow for All Apps") { Task { await allow(nil) } }
                }
                .controlSize(.small)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 10))
    }

    private func allow(_ path: String?) async {
        let remote: RemoteMatch = IPAddress(host) != nil ? .address(host) : .host(host)
        _ = await model.save(Rule(action: .allow, process: path.map(ProcessMatch.path) ?? .any,
                                  codeRequirement: path.flatMap { model.identity(for: $0).designatedRequirement },
                                  remote: remote, notes: "Allowed from Troubleshoot"))
    }
}
