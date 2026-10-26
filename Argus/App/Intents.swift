import AppIntents
import ArgusKit

/// Shortcuts, Siri and Spotlight actions. They run in the app, launching it if needed.
enum ArgusIntentError: Error, CustomLocalizedStringResourceConvertible {
    case notConnected

    var localizedStringResource: LocalizedStringResource {
        "Argus isn't connected to its engine yet. Try again in a moment."
    }
}

/// The running app's model, once it can talk to the engine (launches can take a moment).
@MainActor
private func connectedModel() async throws -> AppModel {
    for _ in 0..<40 {
        if let model = AppModel.shared, model.isConnected { return model }
        try? await Task.sleep(for: .milliseconds(250))
    }
    throw ArgusIntentError.notConnected
}

struct PauseArgusIntent: AppIntent {
    static let title: LocalizedStringResource = "Pause Argus"
    static let description = IntentDescription("Allow every connection for a while. Protection resumes by itself.")

    @Parameter(title: "Minutes", default: 5, inclusiveRange: (1, 1440))
    var minutes: Int

    static var parameterSummary: some ParameterSummary {
        Summary("Pause Argus for \(\.$minutes) minutes")
    }

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        let model = try await connectedModel()
        await model.pause(minutes: minutes)
        return .result(dialog: "Argus is paused for \(minutes) minute\(minutes == 1 ? "" : "s"). Everything is allowed until then.")
    }
}

struct ResumeArgusIntent: AppIntent {
    static let title: LocalizedStringResource = "Resume Argus"
    static let description = IntentDescription("End a pause and start filtering connections again.")

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        let model = try await connectedModel()
        await model.resume()
        return .result(dialog: "Argus is watching again.")
    }
}

enum ArgusModeOption: String, AppEnum {
    case ask, allowSilently, denySilently

    static let typeDisplayRepresentation: TypeDisplayRepresentation = "Argus Mode"
    static let caseDisplayRepresentations: [ArgusModeOption: DisplayRepresentation] = [
        .ask: "Ask Me", .allowSilently: "Allow Silently", .denySilently: "Deny Silently",
    ]

    var mode: FilterMode {
        switch self {
        case .ask: .alert
        case .allowSilently: .silentAllow
        case .denySilently: .silentDeny
        }
    }
}

struct SetArgusModeIntent: AppIntent {
    static let title: LocalizedStringResource = "Set Argus Mode"
    static let description = IntentDescription("Choose what Argus does with connections it hasn't seen before.")

    @Parameter(title: "Mode")
    var mode: ArgusModeOption

    static var parameterSummary: some ParameterSummary {
        Summary("Set Argus to \(\.$mode)")
    }

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        let model = try await connectedModel()
        await model.setMode(mode.mode)
        return .result(dialog: "Argus is set to \(mode.mode.displayName).")
    }
}

struct ArgusStatusIntent: AppIntent {
    static let title: LocalizedStringResource = "Argus Status"
    static let description = IntentDescription("Whether Argus is protecting this Mac, and what it blocked today.")

    @MainActor
    func perform() async throws -> some IntentResult & ReturnsValue<String> & ProvidesDialog {
        let model = try await connectedModel()
        let status: String = if !model.state.settings.protectionEnabled {
            "Argus is off."
        } else if let until = model.pausedUntil {
            "Argus is paused until \(until.formatted(date: .omitted, time: .shortened))."
        } else {
            "Argus is watching in \(model.state.effectiveMode.displayName) mode."
        }
        let summary = "\(status) Today it blocked \(model.today.blocked.formatted()) of \(model.today.connections.formatted()) connections."
        return .result(value: summary, dialog: "\(summary)")
    }
}

struct ArgusShortcuts: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(intent: PauseArgusIntent(), phrases: ["Pause \(.applicationName)", "Pause \(.applicationName) protection"],
                    shortTitle: "Pause Argus", systemImageName: "pause.circle")
        AppShortcut(intent: ResumeArgusIntent(), phrases: ["Resume \(.applicationName)", "Turn \(.applicationName) back on"],
                    shortTitle: "Resume Argus", systemImageName: "play.circle")
        AppShortcut(intent: ArgusStatusIntent(), phrases: ["Is \(.applicationName) on", "\(.applicationName) status"],
                    shortTitle: "Argus Status", systemImageName: "eye")
        AppShortcut(intent: SetArgusModeIntent(), phrases: ["Set \(.applicationName) mode"],
                    shortTitle: "Set Mode", systemImageName: "bell.badge")
    }
}
