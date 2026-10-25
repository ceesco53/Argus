import ArgusKit
import SwiftUI

/// The status menu: a quick glance at what's happening and the most common switches.
struct MenuBarView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            header
            PausedBanner(compact: true)
            if model.engine == .monitor {
                Label("Monitoring only — can't block yet", systemImage: "eye.trianglebadge.exclamationmark")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
            traffic
            modePicker
            profile
            if !model.alerts.isEmpty { waitingAlerts }
            if let network = model.networkPrompt { NetworkPromptView(network: network, compact: true) }
            if !model.recentlyBlocked.isEmpty { recentlyBlocked }
            activeApps
            Divider()
            footer
        }
        .padding(16)
        .frame(width: 340)
        .onAppear {
            let openWindow = openWindow
            WindowOpener.open = { openWindow(id: $0) }
        }
    }

    private var protectionBinding: Binding<Bool> {
        Binding(get: { model.state.settings.protectionEnabled },
                set: { value in Task { await model.setProtection(value) } })
    }

    private var header: some View {
        HStack(spacing: 12) {
            MascotView(asleep: model.isAsleep, size: 46)
            VStack(alignment: .leading, spacing: 2) {
                Text("Argus").font(.headline)
                Text(statusLine).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            PauseMenu {
                Image(systemName: model.pausedUntil == nil ? "pause.circle" : "pause.circle.fill")
                    .font(.title2)
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .fixedSize()
            Toggle("Protection", isOn: protectionBinding)
                .toggleStyle(.switch)
                .labelsHidden()
                .help("Turn protection on or off")
        }
    }

    private var recentlyBlocked: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Recently blocked").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                Spacer()
                Button("Show All") {
                    model.section = .overview
                    openMain()
                }
                .buttonStyle(.link)
                .font(.caption)
            }
            ForEach(model.recentlyBlocked.prefix(4)) { entry in
                BlockedRow(entry: entry, model: model, iconSize: 18)
            }
        }
    }

    private var statusLine: String {
        guard model.state.settings.protectionEnabled else { return "Asleep — everything is allowed" }
        if model.pausedUntil != nil { return "Paused — everything is allowed" }
        switch model.engine {
        case .starting: return "Waking up…"
        case .filter: return "Watching · \(model.state.effectiveMode.displayName)"
        case .monitor: return "Watching · observe only"
        }
    }

    private var traffic: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("Live traffic").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                Spacer()
                RateLabel(rate: model.currentRate)
            }
            ZStack {
                Sparkline(values: model.recentTraffic.suffix(60).map { Double($0.bytesIn) }, color: .incoming)
                Sparkline(values: model.recentTraffic.suffix(60).map { Double($0.bytesOut) }, color: .outgoing)
            }
            .frame(height: 38)
            .padding(8)
            .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
        }
    }

    private var modePicker: some View {
        Picker("When a new connection appears", selection: Binding(
            get: { model.state.settings.mode },
            set: { mode in Task { await model.setMode(mode) } })) {
            ForEach(FilterMode.allCases, id: \.self) { mode in
                Label(mode.displayName, systemImage: mode.symbolName).tag(mode)
            }
        }
        .pickerStyle(.segmented)
        .labelsHidden()
        .disabled(!model.state.settings.protectionEnabled)
        .help(model.state.effectiveMode.explanation)
    }

    private var profile: some View {
        HStack {
            Label("Profile", systemImage: "person.2.crop.square.stack").font(.callout)
            Spacer()
            Menu(model.state.activeProfile?.name ?? "None") {
                Button("None") { Task { await model.activateProfile(nil) } }
                Divider()
                ForEach(model.state.profiles) { profile in
                    Button {
                        Task { await model.activateProfile(profile.id) }
                    } label: {
                        Label(profile.name, systemImage: profile.symbolName)
                    }
                }
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
        }
    }

    private var waitingAlerts: some View {
        Button {
            AppDelegate.showMainWindow()
        } label: {
            Label("\(model.alerts.count) connection\(model.alerts.count == 1 ? "" : "s") waiting for you", systemImage: "bell.badge.fill")
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .buttonStyle(.borderedProminent)
        .tint(.orange)
    }

    private var activeApps: some View {
        let active = model.processRates.sorted { $0.value.total > $1.value.total }.prefix(5)
        return VStack(alignment: .leading, spacing: 8) {
            Text("Active now").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
            if active.isEmpty {
                Text("All quiet.").font(.callout).foregroundStyle(.tertiary)
            }
            ForEach(Array(active), id: \.key) { path, rate in
                let identity = model.identity(for: path)
                Button {
                    model.selectedProcessPath = path
                    model.section = .monitor
                    openMain()
                } label: {
                    HStack(spacing: 8) {
                        AppIconView(identity: identity, size: 20)
                        Text(identity.name).lineLimit(1).truncationMode(.middle)
                        Spacer(minLength: 6)
                        RateLabel(rate: rate).fixedSize()
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
        }
    }

    private var footer: some View {
        HStack {
            Button("Open Argus") { openMain() }
                .keyboardShortcut("o")
            Spacer()
            Button {
                NSApp.activate()
                openSettings()
            } label: {
                Image(systemName: "gearshape")
            }
            .help("Settings")
            Button {
                NSApp.terminate(nil)
            } label: {
                Image(systemName: "power")
            }
            .help("Quit Argus. Filtering continues if the network filter is installed.")
        }
        .buttonStyle(.borderless)
    }

    private func openMain() {
        NSApp.setActivationPolicy(.regular)
        openWindow(id: "main")
        NSApp.activate()
    }
}

/// Asks which profile to use on a network Argus hasn't seen before.
struct NetworkPromptView: View {
    @Environment(AppModel.self) private var model
    let network: NetworkIdentity
    var compact = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("You joined \(network.displayName)", systemImage: network.interface.symbolName)
                .font(compact ? .callout.weight(.semibold) : .headline)
            Text("Which profile should Argus use on this network?")
                .font(.caption)
                .foregroundStyle(.secondary)
            HStack {
                ForEach(model.state.profiles.prefix(compact ? 2 : 4)) { profile in
                    Button {
                        Task { await model.assign(network, to: profile.id) }
                    } label: {
                        Label(profile.name, systemImage: profile.symbolName)
                    }
                }
                Button("No Profile") { Task { await model.assign(network, to: nil) } }
            }
            .controlSize(compact ? .small : .regular)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.accentColor.opacity(0.1), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
    }
}
