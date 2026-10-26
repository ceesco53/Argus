import ArgusKit
import SwiftUI

struct MainWindow: View {
    @Environment(AppModel.self) private var model
    @AppStorage("hasCompletedOnboarding") private var hasCompletedOnboarding = false
    @State private var showOnboarding = false
    @Environment(\.openWindow) private var openWindow
    /// SwiftUI keeps a closed window's views alive and updating every second (hundreds of
    /// megabytes, and steady CPU for an app that mostly sits in the menu bar), so they're
    /// dropped when the window closes and rebuilt when it opens again.
    @State private var isOpen = true

    var body: some View {
        Group {
            if isOpen { content } else { Color.clear }
        }
        .onAppear { isOpen = true }
        .onDisappear { isOpen = false }
    }

    private var content: some View {
        @Bindable var model = model
        return NavigationSplitView {
            List(selection: $model.section) {
                Section("Activity") {
                    row(.overview)
                    row(.monitor, badge: model.alerts.count)
                    row(.map)
                }
                Section("Control") {
                    row(.rules)
                    row(.blocklists)
                    row(.profiles)
                }
                Section("Security") {
                    row(.security, badge: model.bpfUsers.count)
                    row(.capture)
                }
                Section("Help") {
                    row(.troubleshoot, badge: model.health.status.isProblem ? 1 : 0)
                }
            }
            .navigationSplitViewColumnWidth(min: 200, ideal: 220, max: 280)
            .safeAreaInset(edge: .bottom) { SidebarStatus().padding(10) }
        } detail: {
            Group {
                switch model.section ?? .overview {
                case .overview: OverviewView()
                case .monitor: MonitorView()
                case .map: ConnectionsMapView()
                case .rules: RulesView()
                case .blocklists: BlocklistsView()
                case .profiles: ProfilesView()
                case .security: SecurityView()
                case .capture: CaptureView()
                case .troubleshoot: TroubleshootView()
                }
            }
            .frame(minWidth: 640, minHeight: 480)
        }
        .toolbar {
            ToolbarItem(placement: .navigation) {
                LockButton()
            }
        }
        .overlay(alignment: .bottom) {
            if let toast = model.toast {
                ToastView(toast: toast, model: model).padding(.bottom, 22)
            }
        }
        .animation(.snappy, value: model.toast)
        .sheet(isPresented: $model.showReview) { ReviewView().environment(model) }
        .sheet(isPresented: $model.showDigest) { DigestView().environment(model) }
        .sheet(isPresented: $model.showChanges) { RecentChangesView().environment(model) }
        .sheet(isPresented: $showOnboarding) {
            OnboardingView { showOnboarding = false }
                .environment(model)
                .interactiveDismissDisabled()
        }
        .alert("Something went wrong", isPresented: Binding(
            get: { model.errorMessage != nil },
            set: { if !$0 { model.errorMessage = nil } })) {
            Button("OK") { model.errorMessage = nil }
        } message: {
            Text(model.errorMessage ?? "")
        }
        .onAppear {
            let openWindow = openWindow
            WindowOpener.open = { openWindow(id: $0) }
            NSApp.setActivationPolicy(.regular)
            NSApp.activate()
            if !hasCompletedOnboarding { showOnboarding = true }
        }
        .onDisappear {
            DispatchQueue.main.async { AppDelegate.updateActivationPolicy() }
        }
    }

    private func row(_ item: SidebarItem, badge: Int = 0) -> some View {
        Label(item.title, systemImage: item.symbol)
            .badge(badge)
            .tag(item)
    }
}

/// Protection switch and mode at the foot of the sidebar.
struct SidebarStatus: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let enabled = model.state.settings.protectionEnabled
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                MascotView(asleep: model.isAsleep, size: 30)
                VStack(alignment: .leading, spacing: 0) {
                    Text(model.pausedUntil != nil ? "Paused" : enabled ? "Watching" : "Asleep").font(.callout.weight(.semibold))
                    Text(model.engine == .filter ? "Network filter" : model.engine == .monitor ? "Monitor only" : "Starting…")
                        .font(.caption2)
                        .foregroundStyle(model.engine == .monitor ? .orange : .secondary)
                }
                Spacer()
                Toggle("Protection", isOn: Binding(get: { enabled }, set: { value in Task { await model.setProtection(value) } }))
                    .toggleStyle(.switch)
                    .controlSize(.small)
                    .labelsHidden()
            }
        }
        .padding(10)
        .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
    }
}

struct LockButton: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        if model.state.settings.lockEnabled {
            Button {
                if model.isUnlocked { model.lock() } else { Task { await model.unlock() } }
            } label: {
                Image(systemName: model.isUnlocked ? "lock.open" : "lock.fill")
            }
            .help(model.isUnlocked ? "Lock settings again" : "Settings are locked. Click to unlock with an administrator password.")
        }
    }
}
