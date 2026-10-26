import AppIntents
import ArgusKit
import SwiftUI
import WidgetKit

@main
struct ArgusWidgets: WidgetBundle {
    var body: some Widget {
        StatusWidget()
        if #available(macOS 26.0, *) {
            ProtectionControl()
            PauseControl()
        }
    }
}

// MARK: - Status widget

struct StatusEntry: TimelineEntry {
    let date: Date
    let snapshot: WidgetSnapshot?
}

struct StatusProvider: TimelineProvider {
    func placeholder(in context: Context) -> StatusEntry {
        StatusEntry(date: Date(), snapshot: WidgetSnapshot(status: .watching, pausedUntil: nil, mode: .alert, profileName: "Home",
                                                           connectionsToday: 1_284, blockedToday: 312, blockedByListsToday: 280))
    }

    func getSnapshot(in context: Context, completion: @escaping (StatusEntry) -> Void) {
        completion(context.isPreview ? placeholder(in: context) : StatusEntry(date: Date(), snapshot: WidgetSnapshot.load()))
    }

    func getTimeline(in context: Context, completion: @escaping (Timeline<StatusEntry>) -> Void) {
        let snapshot = WidgetSnapshot.load()
        var refresh = Date().addingTimeInterval(15 * 60)
        if let until = snapshot?.pausedUntil, until < refresh { refresh = until.addingTimeInterval(2) } // flip back when the pause ends
        completion(Timeline(entries: [StatusEntry(date: Date(), snapshot: snapshot)], policy: .after(refresh)))
    }
}

struct StatusWidget: Widget {
    var body: some WidgetConfiguration {
        StaticConfiguration(kind: "ArgusStatus", provider: StatusProvider()) { entry in
            StatusWidgetView(entry: entry)
                .containerBackground(.fill.tertiary, for: .widget)
        }
        .configurationDisplayName("Argus")
        .description("Whether Argus is protecting this Mac, and what it blocked today.")
        .supportedFamilies([.systemSmall, .systemMedium])
    }
}

struct StatusWidgetView: View {
    @Environment(\.widgetFamily) private var family
    let entry: StatusEntry

    var body: some View {
        if let snapshot = entry.snapshot {
            if family == .systemSmall { small(snapshot) } else { medium(snapshot) }
        } else {
            VStack(spacing: 6) {
                Image("MascotAsleep").resizable().scaledToFit().frame(width: 54)
                Text("Open Argus to start").font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private func small(_ snapshot: WidgetSnapshot) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Image(snapshot.isAwake ? "MascotAwake" : "MascotAsleep").resizable().scaledToFit().frame(width: 44)
                Spacer()
            }
            Text(snapshot.statusTitle).font(.headline)
            statusDetail(snapshot)
            Spacer(minLength: 0)
            Text("\(snapshot.blockedToday.formatted()) blocked today").font(.caption).foregroundStyle(.secondary)
        }
    }

    private func medium(_ snapshot: WidgetSnapshot) -> some View {
        HStack(spacing: 14) {
            Image(snapshot.isAwake ? "MascotAwake" : "MascotAsleep").resizable().scaledToFit().frame(width: 84)
            VStack(alignment: .leading, spacing: 6) {
                Text(snapshot.statusTitle).font(.headline)
                statusDetail(snapshot)
                HStack(spacing: 14) {
                    metric(snapshot.blockedToday.formatted(), "blocked")
                    metric(snapshot.blockedByListsToday.formatted(), "by lists")
                    metric(snapshot.connectionsToday.formatted(), "connections")
                }
            }
            Spacer(minLength: 0)
        }
    }

    @ViewBuilder
    private func statusDetail(_ snapshot: WidgetSnapshot) -> some View {
        if snapshot.status == .paused, let until = snapshot.pausedUntil, until.timeIntervalSinceNow < 86_400 {
            (Text("Resumes in ") + Text(until, style: .timer)).font(.caption).foregroundStyle(.orange)
        } else {
            Text(snapshot.detail).font(.caption).foregroundStyle(.secondary).lineLimit(2)
        }
    }

    private func metric(_ value: String, _ label: String) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(value).font(.title3.weight(.semibold).monospacedDigit())
            Text(label).font(.caption2).foregroundStyle(.secondary)
        }
    }
}

extension WidgetSnapshot {
    var isAwake: Bool { status == .watching || status == .learning || status == .monitor }

    var statusTitle: String {
        switch status {
        case .watching: "Watching"
        case .learning: "Learning"
        case .monitor: "Monitoring"
        case .paused: "Paused"
        case .off: "Off"
        }
    }

    var detail: String {
        switch status {
        case .watching: [mode.displayName, profileName].compactMap { $0 }.joined(separator: " · ")
        case .learning: "No alerts while learning"
        case .monitor: "Observing only"
        case .paused: "Everything is allowed"
        case .off: "Everything is allowed"
        }
    }
}

// MARK: - Control Center

/// Talks to the network filter directly; controls run without the app.
enum EngineLink {
    static func pause(until: Date?) async throws {
        guard let name = Bundle.main.object(forInfoDictionaryKey: ArgusPaths.machServiceInfoKey) as? String, !name.hasPrefix(".") else {
            throw ArgusError.unsupported("Argus's network filter isn't available in this build.")
        }
        let client = ArgusClient(channel: XPCChannel.connect(machServiceName: name, serverRequirement: nil))
        client.start()
        defer { client.close() }
        _ = try await client.hello(ClientHello(role: .commandLine, wantsAlerts: false))
        try await client.call(.pauseProtection(until: until))
        WidgetCenter.shared.reloadAllTimelines()
    }
}

@available(macOS 26.0, *)
struct ProtectionControl: ControlWidget {
    var body: some ControlWidgetConfiguration {
        StaticControlConfiguration(kind: "ArgusProtection", provider: ProtectionValueProvider()) { isOn in
            ControlWidgetToggle("Argus", isOn: isOn, action: SetProtectionIntent()) { on in
                Label(on ? "Watching" : "Paused", systemImage: on ? "eye" : "pause.circle")
            }
        }
        .displayName("Argus Protection")
        .description("Pause Argus for an hour, or resume it.")
    }
}

@available(macOS 26.0, *)
struct ProtectionValueProvider: ControlValueProvider {
    var previewValue: Bool { true }

    func currentValue() async throws -> Bool {
        guard let snapshot = WidgetSnapshot.load() else { return true }
        return snapshot.status != .paused || (snapshot.pausedUntil.map { $0 < Date() } ?? false)
    }
}

/// Off pauses for an hour (a pause always ends by itself); on resumes.
struct SetProtectionIntent: SetValueIntent {
    static let title: LocalizedStringResource = "Argus Protection"

    @Parameter(title: "Protecting")
    var value: Bool

    func perform() async throws -> some IntentResult {
        try await EngineLink.pause(until: value ? nil : Date().addingTimeInterval(3600))
        return .result()
    }
}

@available(macOS 26.0, *)
struct PauseControl: ControlWidget {
    var body: some ControlWidgetConfiguration {
        StaticControlConfiguration(kind: "ArgusPause5") {
            ControlWidgetButton(action: PauseFiveMinutesIntent()) {
                Label("Pause Argus 5 min", systemImage: "pause.circle")
            }
        }
        .displayName("Pause Argus for 5 Minutes")
        .description("Allow everything for five minutes.")
    }
}

struct PauseFiveMinutesIntent: AppIntent {
    static let title: LocalizedStringResource = "Pause Argus for 5 Minutes"

    func perform() async throws -> some IntentResult {
        try await EngineLink.pause(until: Date().addingTimeInterval(300))
        return .result()
    }
}
