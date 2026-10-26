import ArgusKit
import ServiceManagement
import SwiftUI
import UniformTypeIdentifiers

struct SettingsView: View {
    var body: some View {
        TabView {
            Tab("General", systemImage: "gearshape") { GeneralSettings() }
            Tab("Notifications", systemImage: "bell") { NotificationSettings() }
            Tab("Protection", systemImage: "shield") { ProtectionSettings() }
            Tab("Alerts", systemImage: "bell.badge") { AlertSettings() }
            Tab("Network Filter", systemImage: "network.badge.shield.half.filled") { FilterSettings() }
            Tab("Location", systemImage: "globe") { LocationSettings() }
            Tab("Command Line", systemImage: "terminal") { CommandLineSettings() }
            Tab("Backup", systemImage: "externaldrive") { BackupSettings() }
        }
        .frame(width: 620)
        .frame(minHeight: 380)
    }
}

/// Binds a toggle to an engine setting.
private struct EngineToggle: View {
    @Environment(AppModel.self) private var model
    let title: String
    let detail: String
    let keyPath: WritableKeyPath<FirewallSettings, Bool>

    var body: some View {
        Toggle(isOn: Binding(get: { model.state.settings[keyPath: keyPath] },
                             set: { value in Task { await model.updateSettings { $0[keyPath: keyPath] = value } } })) {
            Text(title)
            Text(detail)
        }
    }
}

private struct GeneralSettings: View {
    @AppStorage("showRateInMenuBar") private var showRate = false
    @AppStorage("hasCompletedOnboarding") private var hasCompletedOnboarding = true
    @State private var launchAtLogin = SMAppService.mainApp.status == .enabled

    var body: some View {
        Form {
            Toggle(isOn: $launchAtLogin) {
                Text("Open Argus at login")
                Text("Argus runs quietly in the menu bar. The network filter keeps working even when the app isn't running.")
            }
            .onChange(of: launchAtLogin) { _, enabled in
                do {
                    if enabled { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
                } catch {
                    launchAtLogin = SMAppService.mainApp.status == .enabled
                }
            }
            Toggle("Show the current data rate in the menu bar", isOn: $showRate)
            CloudSyncToggle()
            if Updater.shared.isConfigured {
                Toggle("Check for updates automatically", isOn: Binding(
                    get: { Updater.shared.checksAutomatically }, set: { Updater.shared.checksAutomatically = $0 }))
                Button("Check for Updates…") { Updater.shared.checkForUpdates() }
            }
            Button("Show the Welcome Guide Again") {
                hasCompletedOnboarding = false
                AppDelegate.showMainWindow()
            }
        }
        .formStyle(.grouped)
    }
}

private struct ProtectionSettings: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        Form {
            Section("Allow without asking") {
                EngineToggle(title: "Software signed by Apple", detail: "macOS services and Apple's own apps.", keyPath: \.allowAppleSoftware)
                EngineToggle(title: "Software from identified developers", detail: "Mac App Store and notarized Developer ID apps. Convenient, but you'll see fewer alerts.", keyPath: \.allowSignedSoftware)
                EngineToggle(title: "Connections within the local network", detail: "Printers, NAS drives, AirPlay and other devices at home.", keyPath: \.allowLocalNetwork)
            }
            Section("Insight") {
                EngineToggle(title: "Learn hostnames from DNS answers", detail: "Lets rules for hostnames apply even when an app connects by IP address.", keyPath: \.learnHostnamesFromDNS)
                EngineToggle(title: "Enforce code signatures", detail: "Block programs whose signature no longer matches their rules.", keyPath: \.enforceCodeSignatures)
            }
            Section("When no one can answer") {
                Picker(selection: Binding(get: { model.state.settings.unattendedAction },
                                          set: { value in Task { await model.updateSettings { $0.unattendedAction = value } } })) {
                    Text("Allow the connection").tag(RuleAction.allow)
                    Text("Deny the connection").tag(RuleAction.deny)
                } label: {
                    Text("If the Argus app isn't running")
                    Text("The network filter keeps working without the app, but can't ask you.")
                }
            }
        }
        .formStyle(.grouped)
    }
}

private struct AlertSettings: View {
    @Environment(AppModel.self) private var model
    @AppStorage("alertDefaultDuration") private var defaultDuration = "forever"
    @AppStorage("quietWhenBusy") private var quietWhenBusy = true
    @AppStorage("pauseForWiFiSignIn") private var pauseForWiFiSignIn = true

    enum TimeoutChoice: Hashable { case deny, allow, followOrDeny, followOrAllow }

    private var timeoutChoice: Binding<TimeoutChoice> {
        Binding {
            let settings = model.state.settings
            switch (settings.alertTimeoutFollowsAdvice, settings.alertTimeoutAction) {
            case (false, .deny): return .deny
            case (false, .allow): return .allow
            case (true, .deny): return .followOrDeny
            case (true, .allow): return .followOrAllow
            }
        } set: { choice in
            Task {
                await model.updateSettings {
                    $0.alertTimeoutFollowsAdvice = choice == .followOrDeny || choice == .followOrAllow
                    $0.alertTimeoutAction = choice == .allow || choice == .followOrAllow ? .allow : .deny
                }
            }
        }
    }

    var body: some View {
        Form {
            Picker("Remember my answer", selection: $defaultDuration) {
                Text("Forever").tag("forever")
                Text("Until the app quits").tag("untilQuit")
                Text("For 1 hour").tag("60")
                Text("For 1 day").tag("1440")
                Text("Until restart").tag("untilRestart")
                Text("Just this once").tag("once")
            }
            Picker("Wait for an answer", selection: Binding(get: { model.state.settings.alertTimeout },
                                                             set: { value in Task { await model.updateSettings { $0.alertTimeout = value } } })) {
                Text("30 seconds").tag(TimeInterval(30))
                Text("1 minute").tag(TimeInterval(60))
                Text("90 seconds").tag(TimeInterval(90))
                Text("2 minutes").tag(TimeInterval(120))
                Text("5 minutes").tag(TimeInterval(300))
            }
            Picker("Then", selection: timeoutChoice) {
                Text("Deny once").tag(TimeoutChoice.deny)
                Text("Allow once").tag(TimeoutChoice.allow)
                Text("Follow a confident suggestion, otherwise deny").tag(TimeoutChoice.followOrDeny)
                Text("Follow a confident suggestion, otherwise allow").tag(TimeoutChoice.followOrAllow)
            }
            Section {
                EngineToggle(title: "Suggest an answer",
                             detail: "Argus weighs HaGeZi's threat and tracker lists (downloaded daily, about 15 MB, used only for advice), who made the app, and your earlier answers.",
                             keyPath: \.suggestAnswers)
            }
            Section("Learning period") {
                if let until = model.learningUntil {
                    LabeledContent("Learning until", value: until.formatted(date: .abbreviated, time: .shortened))
                    HStack {
                        Button("Review Apps…") {
                            model.showReview = true
                            AppDelegate.showMainWindow()
                        }
                        Button("End Learning Now") { Task { await model.endLearning() } }
                    }
                } else {
                    Text("Allow unknown connections quietly for a few days, then review every app at once. Useful after installing Argus or setting up a new Mac.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                    HStack {
                        Button("Learn for 3 Days") { Task { await model.startLearning(days: 3) } }
                        Button("Learn for a Week") { Task { await model.startLearning(days: 7) } }
                    }
                }
            }
            Section("While I'm busy") {
                Toggle(isOn: $quietWhenBusy) {
                    Text("No alerts during calls or while the screen is locked")
                    Text("Unknown connections follow a confident suggestion, otherwise the choice below. They're kept for review.")
                }
                .onChange(of: quietWhenBusy) { model.busy.refresh() }
                Picker("Otherwise", selection: Binding(get: { model.state.settings.busyAction },
                                                       set: { value in Task { await model.updateSettings { $0.busyAction = value } } })) {
                    Text("Allow, and let me review later").tag(RuleAction.allow)
                    Text("Deny, and let me review later").tag(RuleAction.deny)
                }
                .disabled(!quietWhenBusy)
                Toggle(isOn: $pauseForWiFiSignIn) {
                    Text("Pause for Wi-Fi sign-in pages")
                    Text("When a hotel or airport network needs you to sign in, pause protection for 5 minutes.")
                }
            }
            Section {
                Text("Alerts appear in a small floating window and never take focus away from what you're doing. Press Return for the suggested answer or ⌘⌫ to deny.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
    }
}

private struct NotificationSettings: View {
    @Environment(AppModel.self) private var model
    @AppStorage("notifyForegroundBlocks") private var foregroundBlocks = true
    @AppStorage("notifyWarnings") private var warnings = true
    @AppStorage("weeklyReport") private var weeklyReport = true

    var body: some View {
        Form {
            Section {
                Toggle(isOn: $foregroundBlocks) {
                    Text("When Argus blocks the app I'm using")
                    Text("So you know right away when a block might be why something isn't working.")
                }
                Toggle(isOn: $warnings) {
                    Text("Security warnings")
                    Text("Packet sniffers, changed code signatures, failed blocklist updates and heavy data use.")
                }
                Toggle(isOn: $weeklyReport) {
                    Text("Weekly report")
                    Text("A short summary every Monday morning: what was blocked and which apps are new.")
                }
            }
            Section("Data usage") {
                Picker("Warn when one app uses more than", selection: Binding(
                    get: { model.state.settings.dataUsageWarningMB },
                    set: { value in Task { await model.updateSettings { $0.dataUsageWarningMB = value } } })) {
                    Text("Never").tag(0)
                    Text("250 MB a day").tag(250)
                    Text("500 MB a day").tag(500)
                    Text("1 GB a day").tag(1024)
                    Text("5 GB a day").tag(5120)
                    Text("10 GB a day").tag(10_240)
                }
            }
        }
        .formStyle(.grouped)
    }
}

private struct FilterSettings: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let filter = model.filter
        Form {
            Section {
                LabeledContent("Status") {
                    HStack {
                        Circle().fill(filter.status == .enabled ? Color.allowed : .orange).frame(width: 8, height: 8)
                        Text(filter.status.title)
                    }
                }
                if case .failed(let message) = filter.status {
                    Text(message).foregroundStyle(.orange)
                }
                LabeledContent("Argus is using", value: model.engine == .filter ? "The network filter" : "The built-in monitor")
            }
            Section {
                switch filter.status {
                case .unavailable:
                    Text("This copy of Argus was built without Apple's Network Extension entitlement, which Apple only grants to members of the paid Apple Developer Program. It works as a full network monitor, but can't hold or block connections.\n\nTo build the complete firewall, set DEVELOPMENT_TEAM and ARGUS_FILTER_ENABLED = YES in Config/Local.xcconfig, build, and move Argus to the Applications folder.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                case .notInstalled, .failed:
                    Button("Install Network Filter…") { filter.install() }
                case .awaitingApproval:
                    Text("Open System Settings › General › Login Items & Extensions › Network Extensions and allow Argus.")
                        .font(.callout)
                    Button("Open System Settings") {
                        NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension")!)
                    }
                case .disabled:
                    Button("Turn On Network Filter") { Task { await filter.enable() } }
                case .enabled:
                    Button("Turn Off Network Filter") { Task { await filter.disable() } }
                    Button("Uninstall Network Filter…", role: .destructive) { Task { await filter.uninstall() } }
                case .checking, .installing:
                    ProgressView().controlSize(.small)
                }
            }
        }
        .formStyle(.grouped)
        .task { await filter.refresh() }
    }
}

private struct LocationSettings: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        Form {
            Section {
                switch model.geo.status {
                case .missing:
                    LabeledContent("Location data", value: "Not downloaded")
                case .working:
                    LabeledContent("Location data") { ProgressView().controlSize(.small) }
                case .ready(let updated, let ranges):
                    LabeledContent("Location data", value: "\(ranges.formatted()) address ranges")
                    LabeledContent("Updated", value: updated.formatted(date: .abbreviated, time: .omitted))
                case .failed(let message):
                    LabeledContent("Location data") { Text(message).foregroundStyle(.orange) }
                }
                Button(model.geo.isReady ? "Update Now" : "Download") { Task { await model.geo.update() } }
                    .disabled(model.geo.status == .working)
            }
            Section {
                Text("Server locations come from the public statistics of ARIN, RIPE NCC, APNIC, LACNIC and AFRINIC: the country each address block is registered to. Big cloud and CDN networks may serve you from elsewhere. All lookups happen on this Mac.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .formStyle(.grouped)
    }
}

private struct CommandLineSettings: View {
    @State private var message: String?
    private let toolPath = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/argus").path

    var body: some View {
        Form {
            Section {
                Text("The argus command manages rules, profiles, blocklists and captures from Terminal or over SSH. Run it with sudo for remote administration of a locked Mac.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                LabeledContent("Tool") { Text(toolPath).font(.caption.monospaced()).textSelection(.enabled) }
                Button("Install in /usr/local/bin…") { install() }
                if let message { Text(message).font(.callout).foregroundStyle(.secondary) }
            }
            Section("Examples") {
                Text("""
                argus status
                argus rules add deny --process Safari --domain doubleclick.net
                argus profiles activate Work
                argus blocklists add hagezi-light
                argus log --follow
                sudo argus capture start --process curl --seconds 30
                """)
                .font(.callout.monospaced())
                .textSelection(.enabled)
            }
        }
        .formStyle(.grouped)
    }

    private func install() {
        let script = "do shell script \"mkdir -p /usr/local/bin && ln -sf '\(toolPath)' /usr/local/bin/argus\" with administrator privileges"
        var error: NSDictionary?
        NSAppleScript(source: script)?.executeAndReturnError(&error)
        message = error == nil ? "Installed. Open a new Terminal window and run `argus help`." : "Not installed."
    }
}

private struct BackupSettings: View {
    @Environment(AppModel.self) private var model
    @State private var pendingImport: URL?
    @State private var confirmClear = false

    var body: some View {
        Form {
            Section("Configuration") {
                Text("A backup contains your rules, profiles, rule group subscriptions and settings.")
                    .font(.callout).foregroundStyle(.secondary)
                HStack {
                    Button("Export Backup…") { export() }
                    Button("Restore from Backup…") { choose() }
                }
            }
            Section("Activity") {
                Button("Clear Connection History…", role: .destructive) { confirmClear = true }
            }
        }
        .formStyle(.grouped)
        .confirmationDialog("Restore this backup?", isPresented: Binding(get: { pendingImport != nil }, set: { if !$0 { pendingImport = nil } })) {
            Button("Merge with Current Rules") { restore(merge: true) }
            Button("Replace Everything", role: .destructive) { restore(merge: false) }
        } message: {
            Text("Merging keeps your current rules and adds the ones from the backup.")
        }
        .confirmationDialog("Clear all connection history and statistics?", isPresented: $confirmClear) {
            Button("Clear History", role: .destructive) { Task { await model.clearActivity() } }
        }
    }

    private func export() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "Argus Backup \(Date().formatted(.iso8601.year().month().day())).json"
        panel.allowedContentTypes = [.json]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        Task { await model.exportBackup(to: url) }
    }

    private func choose() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.json]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        pendingImport = url
    }

    private func restore(merge: Bool) {
        guard let url = pendingImport else { return }
        pendingImport = nil
        Task { await model.importBackup(from: url, merge: merge) }
    }
}

private struct CloudSyncToggle: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let cloud = model.cloud
        VStack(alignment: .leading, spacing: 4) {
            Toggle(isOn: Binding(get: { cloud.isEnabled && cloud.availability == .available }, set: { cloud.setEnabled($0) })) {
                Text("Sync rules with iCloud")
                Text(detail(cloud))
            }
            .disabled(cloud.availability != .available)
            if let problem = cloud.problem {
                Text(problem).font(.caption).foregroundStyle(.orange)
            }
        }
    }

    private func detail(_ cloud: CloudSync) -> String {
        switch cloud.availability {
        case .notEntitled: "Needs a build signed with iCloud key-value storage (a developer team build)."
        case .signedOut: "Sign in to iCloud in System Settings to sync rules between your Macs."
        case .available:
            if let synced = cloud.lastSynced { "Rules, profiles and blocklists stay the same on your Macs. Last synced \(synced.relative)." }
            else { "Rules, profiles and blocklists stay the same on all your Macs. Temporary rules and settings stay on each Mac." }
        }
    }
}
