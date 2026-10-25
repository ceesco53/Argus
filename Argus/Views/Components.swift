import AppKit
import ArgusKit
import Charts
import SwiftUI

extension Color {
    static let allowed = Color("Feather")
    static let denied = Color(red: 0.93, green: 0.27, blue: 0.36)
    static let unapproved = Color.orange
    static let incoming = Color(red: 0.25, green: 0.62, blue: 1.0)
    static let outgoing = Color(red: 0.62, green: 0.45, blue: 1.0)
}

// MARK: - Icons

@MainActor
enum IconCache {
    private static var cache: [String: NSImage] = [:]

    static func icon(for identity: ProcessIdentity) -> NSImage {
        let key = identity.appBundlePath ?? identity.path
        if let cached = cache[key] { return cached }
        let image: NSImage = if identity.path == "/kernel" {
            NSImage(systemSymbolName: "cpu", accessibilityDescription: nil) ?? NSImage()
        } else if FileManager.default.fileExists(atPath: key) {
            NSWorkspace.shared.icon(forFile: key)
        } else {
            NSWorkspace.shared.icon(for: .unixExecutable)
        }
        cache[key] = image
        return image
    }
}

struct AppIconView: View {
    let identity: ProcessIdentity
    var size: CGFloat = 28

    var body: some View {
        Image(nsImage: IconCache.icon(for: identity))
            .resizable()
            .interpolation(.high)
            .frame(width: size, height: size)
            .accessibilityHidden(true)
    }
}

struct MascotView: View {
    var asleep = false
    var size: CGFloat = 120

    var body: some View {
        Image(asleep ? "MascotAsleep" : "MascotAwake")
            .resizable()
            .interpolation(.high)
            .aspectRatio(contentMode: .fit)
            .frame(width: size, height: size)
            .accessibilityLabel(asleep ? "Argus is asleep" : "Argus is watching")
    }
}

// MARK: - Badges

struct VerdictBadge: View {
    let verdict: Verdict
    var compact = false

    var body: some View {
        let (symbol, text, color) = style
        Label(compact ? "" : text, systemImage: symbol)
            .labelStyle(compact ? AnyLabelStyle(.iconOnly) : AnyLabelStyle(.titleAndIcon))
            .font(.caption.weight(.semibold))
            .foregroundStyle(color)
            .padding(.horizontal, compact ? 0 : 7)
            .padding(.vertical, compact ? 0 : 2)
            .background(compact ? .clear : color.opacity(0.13), in: Capsule())
            .help(text)
    }

    private var style: (String, String, Color) {
        if verdict.reason.isUnapproved && verdict.action == .allow {
            return ("questionmark.circle.fill", verdict.isEnforced ? "Allowed, no rule" : "Seen, no rule", .unapproved)
        }
        switch (verdict.action, verdict.isEnforced) {
        case (.allow, _): return ("checkmark.circle.fill", "Allowed", .allowed)
        case (.deny, true): return ("xmark.octagon.fill", "Denied", .denied)
        case (.deny, false): return ("xmark.octagon", "Would be denied", .denied)
        }
    }
}

struct AnyLabelStyle: LabelStyle {
    private let make: (Configuration) -> AnyView
    init<S: LabelStyle>(_ style: S) { make = { AnyView(style.makeBody(configuration: $0)) } }
    func makeBody(configuration: Configuration) -> some View { make(configuration) }
}

struct SignatureBadge: View {
    let kind: SignatureKind

    var body: some View {
        Label(kind.displayName, systemImage: symbol)
            .font(.caption)
            .foregroundStyle(color)
            .help("Code signature: \(kind.displayName)")
    }

    private var symbol: String {
        switch kind {
        case .apple: "apple.logo"
        case .appStore: "bag"
        case .developerID: "checkmark.seal.fill"
        case .development, .adHoc: "hammer"
        case .unsigned: "exclamationmark.triangle.fill"
        case .invalid: "xmark.seal.fill"
        case .unknown: "questionmark.circle"
        }
    }

    private var color: Color {
        switch kind {
        case .apple, .appStore, .developerID: .secondary
        case .development, .adHoc, .unknown: .orange
        case .unsigned, .invalid: .red
        }
    }
}

struct Pill: View {
    let text: String
    var symbol: String?
    var tint: Color = .accentColor

    var body: some View {
        HStack(spacing: 4) {
            if let symbol { Image(systemName: symbol) }
            Text(text)
        }
        .font(.caption.weight(.semibold))
        .foregroundStyle(tint)
        .padding(.horizontal, 8)
        .padding(.vertical, 3)
        .background(tint.opacity(0.14), in: Capsule())
    }
}

// MARK: - Containers

struct CardModifier: ViewModifier {
    var padding: CGFloat = 16

    func body(content: Content) -> some View {
        content
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(.separator.opacity(0.6)))
    }
}

extension View {
    func card(padding: CGFloat = 16) -> some View { modifier(CardModifier(padding: padding)) }
}

struct CardHeader<Trailing: View>: View {
    let title: String
    var symbol: String?
    @ViewBuilder var trailing: Trailing

    var body: some View {
        HStack {
            if let symbol {
                Image(systemName: symbol).foregroundStyle(.tint)
            }
            Text(title).font(.headline)
            Spacer()
            trailing
        }
    }
}

extension CardHeader where Trailing == EmptyView {
    init(title: String, symbol: String? = nil) {
        self.init(title: title, symbol: symbol) { EmptyView() }
    }
}

struct StatTile: View {
    let title: String
    let value: String
    let symbol: String
    var tint: Color = .accentColor
    var footnote: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: symbol)
                    .font(.title3)
                    .foregroundStyle(tint)
                    .frame(width: 34, height: 34)
                    .background(tint.opacity(0.14), in: RoundedRectangle(cornerRadius: 9, style: .continuous))
                Spacer()
            }
            Text(value)
                .font(.system(.title, design: .rounded, weight: .semibold))
                .monospacedDigit()
                .contentTransition(.numericText())
                .lineLimit(1)
                .minimumScaleFactor(0.7)
            Text(title).font(.subheadline).foregroundStyle(.secondary)
            if let footnote {
                Text(footnote).font(.caption).foregroundStyle(.tertiary)
            }
        }
        .card()
    }
}

// MARK: - Charts

/// Mirrored area chart: data received above the axis, sent below.
struct TrafficChart: View {
    let buckets: [TrafficBucket]
    var resolution: TrafficResolution = .second
    var height: CGFloat = 160

    var body: some View {
        Chart {
            ForEach(buckets, id: \.start) { bucket in
                AreaMark(x: .value("Time", bucket.date), y: .value("Received", perSecond(bucket.bytesIn)), series: .value("Direction", "Received"))
                    .foregroundStyle(LinearGradient(colors: [.incoming.opacity(0.7), .incoming.opacity(0.15)], startPoint: .top, endPoint: .bottom))
                    .interpolationMethod(.monotone)
                AreaMark(x: .value("Time", bucket.date), y: .value("Sent", -perSecond(bucket.bytesOut)), series: .value("Direction", "Sent"))
                    .foregroundStyle(LinearGradient(colors: [.outgoing.opacity(0.15), .outgoing.opacity(0.7)], startPoint: .top, endPoint: .bottom))
                    .interpolationMethod(.monotone)
            }
            RuleMark(y: .value("Zero", 0)).foregroundStyle(.separator)
        }
        .chartYAxis {
            AxisMarks(position: .leading, values: .automatic(desiredCount: 4)) { value in
                AxisGridLine().foregroundStyle(.separator.opacity(0.5))
                AxisValueLabel {
                    if let v = value.as(Double.self) { Text(Formatting.rate(abs(v))).font(.caption2) }
                }
            }
        }
        .chartXAxis {
            AxisMarks(values: .automatic(desiredCount: 6)) { _ in
                AxisValueLabel(format: resolution == .hour ? .dateTime.month(.abbreviated).day().hour() : .dateTime.hour().minute())
            }
        }
        .frame(height: height)
        .accessibilityLabel("Network traffic chart")
    }

    private func perSecond(_ bytes: UInt64) -> Double { Double(bytes) / Double(resolution.seconds) }
}

struct ChartLegend: View {
    var body: some View {
        HStack(spacing: 14) {
            Label("Received", systemImage: "arrow.down.circle.fill").foregroundStyle(Color.incoming)
            Label("Sent", systemImage: "arrow.up.circle.fill").foregroundStyle(Color.outgoing)
        }
        .font(.caption)
    }
}

/// A tiny line for list rows and the menu bar.
struct Sparkline: View {
    let values: [Double]
    var color: Color = .accentColor

    var body: some View {
        GeometryReader { geometry in
            let maximum = max(values.max() ?? 0, 1)
            let step = values.count > 1 ? geometry.size.width / CGFloat(values.count - 1) : 0
            let points = values.enumerated().map { index, value in
                CGPoint(x: CGFloat(index) * step, y: geometry.size.height * (1 - CGFloat(value / maximum)))
            }
            ZStack {
                Path { path in
                    guard let first = points.first else { return }
                    path.move(to: CGPoint(x: first.x, y: geometry.size.height))
                    points.forEach { path.addLine(to: $0) }
                    path.addLine(to: CGPoint(x: points.last!.x, y: geometry.size.height))
                    path.closeSubpath()
                }
                .fill(color.opacity(0.18))
                Path { path in
                    guard let first = points.first else { return }
                    path.move(to: first)
                    points.dropFirst().forEach { path.addLine(to: $0) }
                }
                .stroke(color, style: StrokeStyle(lineWidth: 1.5, lineCap: .round, lineJoin: .round))
            }
        }
        .accessibilityHidden(true)
    }
}

struct RateLabel: View {
    let rate: Rate

    var body: some View {
        HStack(spacing: 8) {
            Label(Formatting.rate(rate.bytesInPerSecond), systemImage: "arrow.down")
                .foregroundStyle(Color.incoming)
            Label(Formatting.rate(rate.bytesOutPerSecond), systemImage: "arrow.up")
                .foregroundStyle(Color.outgoing)
        }
        .labelStyle(TightLabelStyle())
        .font(.caption.monospacedDigit())
    }
}

struct TightLabelStyle: LabelStyle {
    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: 2) {
            configuration.icon.imageScale(.small)
            configuration.title
        }
    }
}

// MARK: - Misc

struct CountryLabel: View {
    let country: Country?

    var body: some View {
        if let country {
            Text("\(country.flag) \(country.name)").lineLimit(1).help("Registered in \(country.name)")
        } else {
            Text("—").foregroundStyle(.tertiary)
        }
    }
}

/// Explains that rules aren't enforced while running as a monitor, with a way to fix it.
struct MonitorModeBanner: View {
    @Environment(AppModel.self) private var model
    var compact = false

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "eye.trianglebadge.exclamationmark")
                .font(.title2)
                .foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 4) {
                Text("Monitor mode: Argus is watching but can't block").font(.headline)
                if !compact {
                    Text(model.filter.isEntitled
                         ? "Install the Argus network filter to hold new connections for your approval and enforce your rules and blocklists."
                         : "This copy of Argus was built without Apple's Network Extension entitlement, so it can observe every connection but not stop one. Your rules are kept and take effect as soon as a signed build installs the filter.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer()
            if model.filter.isEntitled {
                Button("Install Filter…") { model.filter.install() }
                    .buttonStyle(.borderedProminent)
            }
        }
        .padding(14)
        .background(Color.orange.opacity(0.1), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(Color.orange.opacity(0.3)))
    }
}

extension Date {
    var relative: String {
        let seconds = Date().timeIntervalSince(self)
        if seconds < 5 { return "now" }
        if seconds < 60 { return "\(Int(seconds))s ago" }
        return formatted(.relative(presentation: .named, unitsStyle: .abbreviated))
    }
}

extension ProcessRecord {
    var subtitle: String {
        var parts = ["\(connectCount.formatted()) connection\(connectCount == 1 ? "" : "s")"]
        if denyCount > 0 { parts.append("\(denyCount.formatted()) denied") }
        return parts.joined(separator: " · ")
    }
}

/// Opens a search for a hostname so users can find out who's behind it.
func researchURL(for host: String) -> URL? {
    var components = URLComponents(string: "https://duckduckgo.com/")
    components?.queryItems = [URLQueryItem(name: "q", value: "\"\(host)\" what is")]
    return components?.url
}

// MARK: - Pause

/// "Pause for 1 minute / 5 / 30 / 1 hour / until I resume", or "Resume" while paused.
struct PauseMenu<Label: View>: View {
    @Environment(AppModel.self) private var model
    @ViewBuilder var label: Label

    static var choices: [(String, Int?)] { [("1 Minute", 1), ("5 Minutes", 5), ("30 Minutes", 30), ("1 Hour", 60), ("Until I Resume", nil)] }

    var body: some View {
        Menu {
            if model.pausedUntil != nil {
                Button("Resume Protection Now") { Task { await model.resume() } }
                Divider()
                Text("Pause again for…")
            } else {
                Text("Allow everything for…")
            }
            ForEach(Self.choices, id: \.0) { title, minutes in
                Button(title) { Task { await model.pause(minutes: minutes) } }
            }
        } label: {
            label
        }
        .disabled(!model.state.settings.protectionEnabled)
        .help("Temporarily allow everything; protection resumes by itself")
    }
}

/// Shown while protection is paused, with a live countdown and a way out.
struct PausedBanner: View {
    @Environment(AppModel.self) private var model
    var compact = false

    var body: some View {
        if let until = model.pausedUntil {
            HStack(spacing: 10) {
                Image(systemName: "pause.circle.fill")
                    .font(compact ? .title3 : .title2)
                    .foregroundStyle(.orange)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Protection paused: everything is allowed").font(compact ? .callout.weight(.semibold) : .headline)
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        Text(PausedBanner.remaining(until: until, now: context.date))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .monospacedDigit()
                    }
                }
                Spacer()
                Button("Resume") { Task { await model.resume() } }
                    .buttonStyle(.borderedProminent)
                    .tint(.orange)
                    .controlSize(compact ? .small : .regular)
            }
            .padding(compact ? 10 : 14)
            .background(Color.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        }
    }

    static func remaining(until: Date, now: Date) -> String {
        if until.timeIntervalSince(now) > 86_400 * 365 { return "Until you resume it" }
        let seconds = max(0, Int(until.timeIntervalSince(now)))
        let time = seconds >= 3600 ? String(format: "%d:%02d:%02d", seconds / 3600, seconds / 60 % 60, seconds % 60)
            : String(format: "%d:%02d", seconds / 60, seconds % 60)
        return "Resumes by itself in \(time)"
    }
}

/// One recently blocked destination, with why and a way to allow it.
struct BlockedRow: View {
    let entry: FlowLogEntry
    let model: AppModel
    var iconSize: CGFloat = 22

    var body: some View {
        HStack(spacing: 10) {
            AppIconView(identity: model.identity(for: entry.processPath), size: iconSize)
            VStack(alignment: .leading, spacing: 1) {
                Text(entry.remote).lineLimit(1).truncationMode(.middle)
                Text("\(entry.processName) · \(entry.verdict.reason.explanation(in: model.state))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .help(entry.verdict.reason.explanation(in: model.state))
            }
            Spacer(minLength: 6)
            Text(entry.date.relative).font(.caption).foregroundStyle(.tertiary)
            Menu("Allow") {
                Button("Allow for \(entry.processName)") { Task { await model.allow(entry, forAllApps: false) } }
                Button("Allow for All Apps") { Task { await model.allow(entry, forAllApps: true) } }
            }
            .menuStyle(.button)
            .controlSize(.small)
            .fixedSize()
        }
    }
}
