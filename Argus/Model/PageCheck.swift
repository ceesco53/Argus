import AppKit
import ArgusKit
import Foundation

/// A short recording of what one app (usually a browser reloading a page) connects to, so the user
/// can see what was blocked and why, and try letting things through without leaving changes behind.
struct PageCheck: Equatable {
    /// The app being checked.
    struct Target: Equatable {
        /// The program its connections are filed under.
        var path: String
        var name: String
        var bundleIdentifier: String?
        var bundlePath: String?
        var designatedRequirement: String?

        var browser: Browsers.Browser? { Browsers.browser(bundleIdentifier: bundleIdentifier) }
        var isBrowser: Bool { browser != nil }
    }

    /// How long a check records after it starts (or after the last reload Argus asked for).
    static let recordingTime: TimeInterval = 20
    /// How long a "try it" decision lasts before Argus undoes it by itself.
    static let trialMinutes = 15

    let id = UUID()
    let target: Target
    var started: Date
    var recordingEnds: Date
    /// The front tab's address when the check started, if the browser told Argus.
    var site: URL?
    /// Whether Argus reloaded the page itself (false: the user has to).
    var reloadedByArgus = false
    var entries: [FlowLogEntry] = []
    /// Temporary rules made from this check, by server.
    var trials: [String: UUID] = [:]
    var search: CulpritSearch?
    /// The temporary rules letting the current test's servers through.
    var searchRules: [UUID] = []

    var isRecording: Bool { Date() < recordingEnds }

    /// The registrable domain of the page, so its own servers can be told from everyone else's.
    var siteDomain: String? { site?.host().flatMap(DomainName.registrableDomain) }

    /// One server the app reached (or tried to) during the check.
    struct Row: Identifiable, Equatable {
        var host: String
        var attempts: Int
        var latest: Verdict
        /// The first time it was denied in this check, which stays the reason after a trial lets it through.
        var firstDenial: Verdict?
        var isSite: Bool

        var id: String { host }
        var wasBlocked: Bool { firstDenial != nil }
    }

    /// Servers in order of first appearance.
    var rows: [Row] {
        var order: [String] = []
        var byHost: [String: Row] = [:]
        let siteDomain = self.siteDomain
        for entry in entries {
            if var row = byHost[entry.remote] {
                row.attempts += 1
                row.latest = entry.verdict
                if row.firstDenial == nil, entry.verdict.action == .deny { row.firstDenial = entry.verdict }
                byHost[entry.remote] = row
            } else {
                order.append(entry.remote)
                let isSite = siteDomain != nil && DomainName.registrableDomain(of: entry.remote) == siteDomain
                byHost[entry.remote] = Row(host: entry.remote, attempts: 1, latest: entry.verdict,
                                           firstDenial: entry.verdict.action == .deny ? entry.verdict : nil, isSite: isSite)
            }
        }
        return order.compactMap { byHost[$0] }
    }

    /// Servers still being blocked (not counting ones let through from this check).
    var blockedHosts: [String] {
        rows.filter { $0.latest.action == .deny && trials[$0.host] == nil && !searchRuleHosts.contains($0.host) }.map(\.host)
    }

    /// Hosts the culprit search currently lets through.
    var searchRuleHosts: Set<String> { Set(search?.testing ?? []) }
}

/// Asks a browser, through AppleScript, for its front tab and to reload it. macOS asks the user
/// the first time; if they say no, or the browser can't be scripted, the user reloads by hand.
enum BrowserScripting {
    static func frontTabURL(of target: PageCheck.Target) async -> URL? {
        guard let script = script(for: target, reload: false) else { return nil }
        guard let output = await run(script), let url = URL(string: output), url.host() != nil else { return nil }
        return url
    }

    /// Reloads the front tab. False when Argus couldn't.
    static func reloadFrontTab(of target: PageCheck.Target) async -> Bool {
        guard let script = script(for: target, reload: true) else { return false }
        return await run(script) != nil
    }

    static func canScript(_ target: PageCheck.Target) -> Bool { script(for: target, reload: false) != nil }

    private static func script(for target: PageCheck.Target, reload: Bool) -> String? {
        // The demo's browsers are made up: never script the real ones.
        guard !DebugLaunch.demo, let id = target.bundleIdentifier, let scripting = target.browser?.scripting,
              id.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" }),
              !NSRunningApplication.runningApplications(withBundleIdentifier: id).isEmpty else { return nil }
        switch (scripting, reload) {
        case (.safari, false):
            return "tell application id \"\(id)\" to get URL of current tab of front window"
        case (.safari, true):
            return """
            tell application id "\(id)"
                set theTab to current tab of front window
                set URL of theTab to (URL of theTab)
            end tell
            return "ok"
            """
        case (.chromium, false):
            return "tell application id \"\(id)\" to get URL of active tab of front window"
        case (.chromium, true):
            return """
            tell application id "\(id)" to reload active tab of front window
            return "ok"
            """
        }
    }

    /// Runs a script with `osascript`, off the main thread. nil when it failed or took too long
    /// (the permission question waits for the user, so the limit is generous).
    private static func run(_ source: String) async -> String? {
        await withCheckedContinuation { continuation in
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            process.arguments = ["-e", source]
            let output = Pipe()
            process.standardOutput = output
            process.standardError = FileHandle.nullDevice
            let finished = Locked(false)
            @Sendable func finish(_ value: String?) {
                guard finished.withLock({ done in defer { done = true }; return !done }) else { return }
                continuation.resume(returning: value)
            }
            process.terminationHandler = { process in
                let data = output.fileHandleForReading.readDataToEndOfFile()
                let text = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
                finish(process.terminationStatus == 0 ? text : nil)
            }
            do {
                try process.run()
            } catch {
                finish(nil)
                return
            }
            DispatchQueue.global().asyncAfter(deadline: .now() + 90) {
                if process.isRunning { process.terminate() }
                finish(nil)
            }
        }
    }
}
