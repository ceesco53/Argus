import ArgusKit
import SwiftUI

@main
struct ArgusApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @AppStorage("hasCompletedOnboarding") private var hasCompletedOnboarding = false
    @AppStorage(Terms.acceptedVersionKey) private var acceptedTermsVersion = 0

    private var termsAccepted: Bool { acceptedTermsVersion >= Terms.version }

    var body: some Scene {
        // Argus lives in the menu bar; the main window only opens when asked (or on first run).
        Window("Argus", id: "main") {
            MainWindow()
                .environment(appDelegate.model)
        }
        .defaultSize(width: 1280, height: 800)
        .windowToolbarStyle(.unified)
        .defaultLaunchBehavior(termsAccepted && (!hasCompletedOnboarding || DebugLaunch.section != nil) ? .presented : .suppressed)
        .commands { ArgusCommands(model: appDelegate.model) }

        Settings {
            SettingsView()
                .environment(appDelegate.model)
        }

        Window("Terms of Use", id: "terms") {
            TermsView()
        }
        .windowResizability(.contentSize)
        .defaultLaunchBehavior(.suppressed)

        MenuBarExtra(isInserted: .constant(termsAccepted)) {
            MenuBarView()
                .environment(appDelegate.model)
        } label: {
            MenuBarLabel(model: appDelegate.model)
        }
        .menuBarExtraStyle(.window)
    }
}

struct ArgusCommands: Commands {
    let model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some Commands {
        CommandGroup(after: .help) {
            Button("Argus Terms of Use") { openWindow(id: "terms") }
        }
        CommandGroup(after: .sidebar) {
            ForEach(Array(SidebarItem.allCases.enumerated()), id: \.element) { index, item in
                Button(item.title) { model.section = item }
                    .keyboardShortcut(KeyEquivalent(Character("\(index + 1)")), modifiers: .command)
            }
        }
        CommandGroup(after: .appInfo) {
            if Updater.shared.isConfigured {
                Button("Check for Updates…") { Updater.shared.checkForUpdates() }
            }
        }
        CommandGroup(after: .undoRedo) {
            Button("Undo Last Argus Change") { Task { await model.undoLast() } }
                .keyboardShortcut("z", modifiers: [.command, .option])
            Button("Recent Changes…") {
                model.showChanges = true
                AppDelegate.showMainWindow()
            }
        }
        CommandMenu("Protection") {
            Button(model.state.settings.protectionEnabled ? "Turn Protection Off" : "Turn Protection On") {
                Task { await model.setProtection(!model.state.settings.protectionEnabled) }
            }
            .keyboardShortcut("p", modifiers: [.command, .shift])
            Menu("Pause Protection") {
                ForEach(PauseMenu<EmptyView>.choices, id: \.0) { title, minutes in
                    Button(title) { Task { await model.pause(minutes: minutes) } }
                }
            }
            .disabled(!model.state.settings.protectionEnabled)
            Button("Resume Protection") { Task { await model.resume() } }
                .disabled(model.pausedUntil == nil)
            Divider()
            Button("Troubleshoot…") { model.troubleshoot(appPath: nil) }
            Button("Review Apps…") {
                model.showReview = true
                AppDelegate.showMainWindow()
            }
            Button("Weekly Report…") {
                model.showDigest = true
                AppDelegate.showMainWindow()
            }
            Divider()
            ForEach(FilterMode.allCases, id: \.self) { mode in
                Button(mode.displayName) { Task { await model.setMode(mode) } }
            }
        }
    }
}

struct MenuBarLabel: View {
    let model: AppModel
    @AppStorage("showRateInMenuBar") private var showRate = false
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        HStack(spacing: 4) {
            Image("MenuBarGlyph")
            if !model.alerts.isEmpty {
                Text("\(model.alerts.count)")
            } else if !model.state.settings.protectionEnabled {
                Text("Off")
            } else if model.pausedUntil != nil {
                Text("Paused")
            } else if showRate {
                Text(Formatting.rate(model.currentRate.total)).monospacedDigit()
            }
        }
        .accessibilityLabel("Argus")
        .onAppear {
            let openWindow = openWindow
            WindowOpener.open = { openWindow(id: $0) }
        }
    }
}

/// Development aid: `-ArgusDebugSection monitor` opens the main window on that section at launch.
enum DebugLaunch {
    /// `-ArgusDebugDownloadLocation YES` fetches the location database at launch.
    static var downloadLocation: Bool {
        #if DEBUG
        UserDefaults.standard.bool(forKey: "ArgusDebugDownloadLocation")
        #else
        false
        #endif
    }

    static var section: SidebarItem? {
        #if DEBUG
        UserDefaults.standard.string(forKey: "ArgusDebugSection").flatMap(SidebarItem.init(rawValue:))
        #else
        nil
        #endif
    }
}
