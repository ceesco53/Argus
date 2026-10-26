import AppKit
import ArgusKit
import SwiftUI

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let model = AppModel()
    private var alertPanel: AlertPanelController?
    private var windowObserver: NSObjectProtocol?
    private var termsWindow: NSWindow?

    func applicationDidFinishLaunching(_ notification: Notification) {
        AppModel.shared = model
        // Nothing starts (engine, alerts, menu bar item) until the terms are accepted.
        guard Terms.isAccepted else {
            presentTerms()
            return
        }
        launch()
    }

    /// The first-run agreement. Declining quits Argus.
    private func presentTerms() {
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 640, height: 660), styleMask: [.titled], backing: .buffered, defer: false)
        window.title = "Argus Terms of Use"
        window.isReleasedWhenClosed = false
        let host = NSHostingController(rootView: TermsView(
            requiresAgreement: true,
            onAgree: { [weak self] in self?.termsAccepted() },
            onDecline: { NSApp.terminate(nil) }))
        host.sizingOptions = []
        window.contentViewController = host
        window.setContentSize(NSSize(width: 640, height: 660))
        window.center()
        termsWindow = window
        NSApp.setActivationPolicy(.regular)
        NSApp.activate()
        window.makeKeyAndOrderFront(nil)
    }

    private func termsAccepted() {
        Terms.accept()
        termsWindow?.close()
        termsWindow = nil
        launch()
        Task {
            // Give SwiftUI a moment to add the menu bar item, which knows how to open windows.
            try? await Task.sleep(for: .milliseconds(300))
            if UserDefaults.standard.bool(forKey: "hasCompletedOnboarding") {
                AppDelegate.updateActivationPolicy()
            } else {
                AppDelegate.showMainWindow()
            }
        }
    }

    private func launch() {
        alertPanel = AlertPanelController(model: model)
        model.onAlertsChanged = { [weak self] in self?.alertPanel?.update() }
        Task {
            await model.start()
            #if DEBUG
            if UserDefaults.standard.bool(forKey: "ArgusDebugAlert") { model.showSampleAlert() }
            if UserDefaults.standard.bool(forKey: "ArgusDebugMenu") { showMenuPreview() }
            switch UserDefaults.standard.string(forKey: "ArgusDebugSheet") {
            case "review": model.showReview = true
            case "digest": model.showDigest = true
            case "changes": model.showChanges = true
            default: break
            }
            #endif
        }

        // Show a Dock icon only while a regular window is open, like a proper background utility.
        windowObserver = NotificationCenter.default.addObserver(forName: NSWindow.willCloseNotification, object: nil, queue: .main) { _ in
            DispatchQueue.main.async { AppDelegate.updateActivationPolicy() }
        }
    }

    #if DEBUG
    private var menuPreview: NSPanel?

    /// The status menu's content in an ordinary window, for screenshots.
    private func showMenuPreview() {
        let panel = NSPanel(contentRect: NSRect(x: 200, y: 200, width: 340, height: 600), styleMask: [.titled, .closable], backing: .buffered, defer: false)
        panel.title = "Menu Preview"
        panel.hidesOnDeactivate = false
        let host = NSHostingController(rootView: MenuBarView().environment(model))
        host.sizingOptions = [] // tracking the preferred size loops on wrapping text (see AlertPanelController)
        panel.contentViewController = host
        panel.setContentSize(host.view.fittingSize)
        panel.center()
        panel.orderFrontRegardless()
        menuPreview = panel
    }
    #endif

    func applicationWillTerminate(_ notification: Notification) {
        model.shutdown()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if let termsWindow {
            termsWindow.makeKeyAndOrderFront(nil)
            return false
        }
        if !flag { AppDelegate.showMainWindow() }
        return true
    }

    static func updateActivationPolicy() {
        let hasWindow = NSApp.windows.contains { window in
            window.isVisible && window.canBecomeMain && !(window is NSPanel) && window.level == .normal
        }
        let policy: NSApplication.ActivationPolicy = hasWindow ? .regular : .accessory
        if NSApp.activationPolicy() != policy { NSApp.setActivationPolicy(policy) }
    }

    /// Brings up the main window from AppKit code (the alert panel, notifications).
    static func showMainWindow() {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate()
        if let window = NSApp.windows.first(where: { $0.identifier?.rawValue.hasPrefix("main") == true }) {
            window.makeKeyAndOrderFront(nil)
        } else if let open = WindowOpener.open {
            open("main")
        } else if let menu = NSApp.windowsMenu, let index = menu.items.firstIndex(where: { $0.title == "Argus" }) {
            // SwiftUI lists the closed window in the Window menu; choosing it reopens the window.
            menu.performActionForItem(at: index)
        }
    }
}

/// SwiftUI's `openWindow`, captured from the always-present menu bar label for use from AppKit.
@MainActor
enum WindowOpener {
    static var open: ((String) -> Void)?
}

/// A floating panel that asks about held connections, one at a time, without stealing focus
/// from the app the user is working in.
@MainActor
final class AlertPanelController {
    private let model: AppModel
    private var panel: NSPanel?
    /// The alert's natural height, as last reported by the view.
    private var contentHeight: CGFloat = 0
    private var moveObserver: NSObjectProtocol?

    static let width: CGFloat = 470
    private static let leftKey = "AlertPanelLeft"
    private static let topKey = "AlertPanelTop"

    init(model: AppModel) {
        self.model = model
        // Frames saved by an earlier version's window autosave could be off screen or zero-sized.
        UserDefaults.standard.removeObject(forKey: "NSWindow Frame ArgusAlertPanel")
    }

    func update() {
        guard !model.alerts.isEmpty else {
            panel?.orderOut(nil)
            return
        }
        let panel = self.panel ?? makePanel()
        self.panel = panel
        if !panel.isVisible {
            place(panel, height: contentHeight > 1 ? contentHeight : 420)
            panel.orderFrontRegardless()
            panel.makeKey()
            NSSound(named: "Tink")?.play()
        }
    }

    private func makePanel() -> NSPanel {
        // The window follows the content's height, never the other way round: letting AppKit and
        // SwiftUI negotiate the size (preferredContentSize) ends in a layout loop with wrapped text.
        let view = AlertView { [weak self] height in self?.resize(toHeight: height) }
        let host = NSHostingController(rootView: view.environment(model))
        host.sizingOptions = []
        // Borderless: a title bar would add a safe-area inset that feeds back into the size.
        let panel = AlertPanel(contentRect: NSRect(x: 0, y: 0, width: Self.width, height: 420),
                               styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false)
        panel.contentViewController = host
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = true
        panel.isMovableByWindowBackground = true
        panel.level = .floating
        panel.hidesOnDeactivate = false
        panel.isReleasedWhenClosed = false
        panel.becomesKeyOnlyIfNeeded = false
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        // Remember where the user drags it (its top-left corner, so a taller alert grows downwards).
        moveObserver = NotificationCenter.default.addObserver(forName: NSWindow.didMoveNotification, object: panel, queue: .main) { [weak panel] _ in
            MainActor.assumeIsolated {
                guard let panel, panel.isVisible, panel.frame.height > 10 else { return }
                UserDefaults.standard.set(panel.frame.minX, forKey: Self.leftKey)
                UserDefaults.standard.set(panel.frame.maxY, forKey: Self.topKey)
            }
        }
        return panel
    }

    /// Matches the panel to the alert's height, keeping its top edge where it is (but on screen).
    private func resize(toHeight height: CGFloat) {
        guard height > 1 else { return }
        contentHeight = height
        // Applied even while hidden: the height is often reported before the panel is shown,
        // and isn't reported again unless it changes.
        guard let panel else { return }
        guard panel.frame.height > 10 else {
            place(panel, height: height)
            return
        }
        guard abs(panel.frame.height - height) > 0.5 || panel.frame.width != Self.width else { return }
        let frame = NSRect(x: panel.frame.minX, y: panel.frame.maxY - height, width: Self.width, height: height)
        panel.setFrame(Self.keepOnScreen(frame, screen: panel.screen), display: true)
    }

    /// Where the user last put the panel, or the top-right corner; always fully on a screen.
    private func place(_ panel: NSPanel, height: CGFloat) {
        let defaults = UserDefaults.standard
        var frame: NSRect
        if defaults.object(forKey: Self.leftKey) != nil, defaults.object(forKey: Self.topKey) != nil {
            let top = defaults.double(forKey: Self.topKey)
            frame = NSRect(x: defaults.double(forKey: Self.leftKey), y: top - height, width: Self.width, height: height)
        } else {
            let visible = (NSScreen.main ?? NSScreen.screens.first)?.visibleFrame ?? .zero
            frame = NSRect(x: visible.maxX - Self.width - 18, y: visible.maxY - height - 18, width: Self.width, height: height)
        }
        panel.setFrame(Self.keepOnScreen(frame, screen: nil), display: true)
    }

    /// Moves `frame` the least distance needed to fit a screen's visible area; if it's taller
    /// than the screen, its top stays visible.
    static func keepOnScreen(_ frame: NSRect, screen: NSScreen?) -> NSRect {
        let screen = screen ?? NSScreen.screens.max { $0.visibleFrame.intersection(frame).area < $1.visibleFrame.intersection(frame).area }
        guard let visible = (screen ?? NSScreen.main)?.visibleFrame else { return frame }
        let margin: CGFloat = 8
        var fitted = frame
        fitted.origin.x = min(max(fitted.minX, visible.minX + margin), visible.maxX - fitted.width - margin)
        fitted.origin.y = max(fitted.minY, visible.minY + margin)
        fitted.origin.y = min(fitted.minY, visible.maxY - fitted.height - margin)
        return fitted
    }
}

private extension NSRect {
    var area: CGFloat { isNull ? 0 : width * height }
}

/// Borderless panels can't become key by default; alerts need the keyboard for Return and ⌘⌫.
final class AlertPanel: NSPanel {
    override var canBecomeKey: Bool { true }
}
