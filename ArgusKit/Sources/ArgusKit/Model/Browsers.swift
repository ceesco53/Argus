import Foundation

/// Web browsers Argus knows, for lists that apply to browsers only and for checking a page.
public enum Browsers {
    /// How Argus can ask a browser for its front tab and reload it (with the user's permission).
    public enum Scripting: Sendable {
        /// `current tab of front window`
        case safari
        /// `active tab of front window`
        case chromium
    }

    public struct Browser: Sendable, Hashable {
        public let bundleIdentifier: String
        public let name: String
        public let scripting: Scripting?
    }

    /// By bundle identifier. Variants (Chrome Canary is com.google.Chrome.canary) and helpers
    /// (com.google.Chrome.helper) are matched by prefix.
    public static let known: [String: Browser] = {
        let list: [(String, String, Scripting?)] = [
            ("com.apple.Safari", "Safari", .safari),
            ("com.apple.SafariTechnologyPreview", "Safari Technology Preview", .safari),
            ("com.google.Chrome", "Google Chrome", .chromium),
            ("org.chromium.Chromium", "Chromium", .chromium),
            ("com.microsoft.edgemac", "Microsoft Edge", .chromium),
            ("com.brave.Browser", "Brave", .chromium),
            ("com.vivaldi.Vivaldi", "Vivaldi", .chromium),
            ("company.thebrowser.Browser", "Arc", nil),
            ("company.thebrowser.dia", "Dia", nil),
            ("com.operasoftware.Opera", "Opera", nil),
            ("com.operasoftware.OperaGX", "Opera GX", nil),
            ("org.mozilla.firefox", "Firefox", nil),
            ("org.mozilla.firefoxdeveloperedition", "Firefox Developer Edition", nil),
            ("org.mozilla.nightly", "Firefox Nightly", nil),
            ("com.kagi.kagimacOS", "Orion", nil),
            ("app.zen-browser.zen", "Zen", nil),
            ("com.duckduckgo.macos.browser", "DuckDuckGo", nil),
        ]
        return Dictionary(uniqueKeysWithValues: list.map { ($0.0, Browser(bundleIdentifier: $0.0, name: $0.1, scripting: $0.2)) })
    }()

    public static func browser(bundleIdentifier: String?) -> Browser? {
        guard let id = bundleIdentifier else { return nil }
        if let exact = known[id] { return exact }
        // Walk up "com.google.Chrome.canary" → "com.google.Chrome".
        var parts = id.split(separator: ".")
        while parts.count > 2 {
            parts.removeLast()
            if let browser = known[parts.joined(separator: ".")] { return browser }
        }
        return nil
    }

    public static func isBrowser(_ identity: ProcessIdentity) -> Bool { browser(bundleIdentifier: identity.bundleIdentifier) != nil }
}

extension FlowContext {
    /// Made by a web browser (including connections its helpers make for it).
    public var isBrowser: Bool {
        Browsers.isBrowser(process) || (viaIsHelper && via.map(Browsers.isBrowser) == true)
    }
}
