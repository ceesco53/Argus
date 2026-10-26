import AppKit
import ArgusKit
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
            .accessibilityLabel(text)
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
        .accessibilityElement(children: .combine)
    }
}

// MARK: - Charts

/// Mirrored area chart: data received above the axis, sent below.
///
/// Drawn with Canvas rather than Swift Charts: the live chart redraws every second, and Charts
/// keeps every axis label it ever made (hundreds of megabytes an hour), which also made each
/// redraw slower.
struct TrafficChart: View {
    let buckets: [TrafficBucket]
    var resolution: TrafficResolution = .second
    var height: CGFloat = 160

    var body: some View {
        Canvas { context, size in draw(in: &context, size: size) }
            .frame(height: height)
            .accessibilityElement()
            .accessibilityLabel("Network traffic chart")
            .accessibilityValue("Received \(Formatting.bytes(buckets.reduce(0) { $0 + $1.bytesIn })), sent \(Formatting.bytes(buckets.reduce(0) { $0 + $1.bytesOut }))")
    }

    private func draw(in context: inout GraphicsContext, size: CGSize) {
        let points = buckets.sorted { $0.start < $1.start }
        let seconds = Double(resolution.seconds)
        let received = points.map { Double($0.bytesIn) / seconds }
        let sent = points.map { -Double($0.bytesOut) / seconds }
        // At least 4 B/s tall, so a quiet network doesn't get fractional "0 B/s" labels. Steps are
        // round in the unit the labels use (1 MB/s, not 977 KB/s).
        let lower = min(0, sent.min() ?? 0), upper = max(4, received.max() ?? 0)
        var unit = pow(1024, (log(max(-lower, upper)) / log(1024)).rounded(.down))
        var steps = ChartTicks.values(covering: lower / unit, upper / unit, desiredCount: 4)
        if steps.contains(where: { abs($0) >= 1000 }) { // 1 MB/s rather than 1,000 KB/s
            unit *= 1024
            steps = ChartTicks.values(covering: lower / unit, upper / unit, desiredCount: 4)
        }
        let yTicks = steps.map { $0 * unit }
        guard let yLow = yTicks.first, let yHigh = yTicks.last, yHigh > yLow else { return }

        // Rate labels on the left; time labels underneath.
        let yLabels = yTicks.map { context.resolve(Text(Formatting.rate(abs($0))).font(.caption2).foregroundStyle(.secondary)) }
        let labelWidth = yLabels.map { $0.measure(in: size).width }.max() ?? 0
        let plot = CGRect(x: labelWidth + 6, y: 5, width: max(1, size.width - labelWidth - 6), height: max(1, size.height - 25))
        func y(_ value: Double) -> CGFloat { plot.maxY - CGFloat((value - yLow) / (yHigh - yLow)) * plot.height }

        for (value, label) in zip(yTicks, yLabels) {
            var grid = Path()
            grid.move(to: CGPoint(x: plot.minX, y: y(value)))
            grid.addLine(to: CGPoint(x: plot.maxX, y: y(value)))
            context.stroke(grid, with: .style(.separator.opacity(0.5)), lineWidth: 0.5)
            context.draw(label, at: CGPoint(x: labelWidth, y: y(value)), anchor: .trailing)
        }

        if let first = points.first?.date, let last = points.last?.date, last > first {
            let span = last.timeIntervalSince(first)
            func x(_ date: Date) -> CGFloat { plot.minX + CGFloat(date.timeIntervalSince(first) / span) * plot.width }

            let ticks = ChartTicks.dates(from: first, to: last, desiredCount: 6)
            // As precise as the spacing: 4:32:30 PM, 4:40 PM or Oct 19, never the same label twice.
            let step = ticks.count > 1 ? ticks[1].timeIntervalSince(ticks[0]) : span
            let format: Date.FormatStyle = step < 60 ? .dateTime.hour().minute().second()
                : step < 86_400 ? .dateTime.hour().minute() : .dateTime.month(.abbreviated).day()
            for tick in ticks {
                let label = context.resolve(Text(tick.formatted(format)).font(.caption2).foregroundStyle(.secondary))
                let half = label.measure(in: size).width / 2
                let center = min(max(x(tick), plot.minX + half), size.width - half)
                context.draw(label, at: CGPoint(x: center, y: plot.maxY + 4), anchor: .top)
            }

            let zero = y(0)
            func area(_ values: [Double]) -> Path {
                let line = zip(points, values).map { CGPoint(x: x($0.date), y: y($1)) }
                var path = Path()
                path.move(to: CGPoint(x: line[0].x, y: zero))
                path.addLine(to: line[0])
                TrafficChart.addMonotoneCurve(through: line, to: &path)
                path.addLine(to: CGPoint(x: line[line.count - 1].x, y: zero))
                path.closeSubpath()
                return path
            }
            context.fill(area(received), with: .linearGradient(
                Gradient(colors: [.incoming.opacity(0.7), .incoming.opacity(0.15)]),
                startPoint: CGPoint(x: 0, y: plot.minY), endPoint: CGPoint(x: 0, y: zero)))
            context.fill(area(sent), with: .linearGradient(
                Gradient(colors: [.outgoing.opacity(0.15), .outgoing.opacity(0.7)]),
                startPoint: CGPoint(x: 0, y: zero), endPoint: CGPoint(x: 0, y: plot.maxY)))
        }

        var axis = Path()
        axis.move(to: CGPoint(x: plot.minX, y: y(0)))
        axis.addLine(to: CGPoint(x: plot.maxX, y: y(0)))
        context.stroke(axis, with: .style(.separator), lineWidth: 1)
    }

    /// A smooth curve through `points` that never overshoots them (monotone cubic interpolation,
    /// like Charts' `.monotone`). `path` must already be at the first point.
    static func addMonotoneCurve(through points: [CGPoint], to path: inout Path) {
        let count = points.count
        guard count > 2 else {
            if count == 2 { path.addLine(to: points[1]) }
            return
        }
        let slopes = (0..<count - 1).map { i in
            let dx = points[i + 1].x - points[i].x
            return dx == 0 ? 0 : (points[i + 1].y - points[i].y) / dx
        }
        var tangents = [CGFloat](repeating: 0, count: count)
        tangents[0] = slopes[0]
        tangents[count - 1] = slopes[count - 2]
        for i in 1..<count - 1 {
            tangents[i] = slopes[i - 1] * slopes[i] <= 0 ? 0 : (slopes[i - 1] + slopes[i]) / 2
        }
        // Fritsch–Carlson: flat segments stay flat, and steep tangents are limited so the curve
        // can't swing past its neighbours.
        for i in 0..<count - 1 {
            guard slopes[i] != 0 else {
                tangents[i] = 0
                tangents[i + 1] = 0
                continue
            }
            let a = tangents[i] / slopes[i], b = tangents[i + 1] / slopes[i]
            let length = a * a + b * b
            if length > 9 {
                let scale = 3 / length.squareRoot()
                tangents[i] = scale * a * slopes[i]
                tangents[i + 1] = scale * b * slopes[i]
            }
        }
        for i in 0..<count - 1 {
            let third = (points[i + 1].x - points[i].x) / 3
            path.addCurve(to: points[i + 1],
                          control1: CGPoint(x: points[i].x + third, y: points[i].y + tangents[i] * third),
                          control2: CGPoint(x: points[i + 1].x - third, y: points[i + 1].y - tangents[i + 1] * third))
        }
    }
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
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Receiving \(Formatting.rate(rate.bytesInPerSecond)), sending \(Formatting.rate(rate.bytesOutPerSecond))")
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

// MARK: - Undo messages

/// "Allowed Safari → news.google.com · Undo", shown briefly after a change.
struct ToastView: View {
    let toast: Toast
    let model: AppModel

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: toast.changeID == nil ? "checkmark.circle.fill" : "arrow.uturn.backward.circle.fill")
                .foregroundStyle(toast.changeID == nil ? Color.allowed : Color.accentColor)
            Text(toast.message).lineLimit(2)
            if let id = toast.changeID {
                Button("Undo") { Task { await model.undo(id) } }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
            }
            Button {
                model.dismissToast()
            } label: {
                Image(systemName: "xmark").font(.caption.weight(.bold))
            }
            .buttonStyle(.borderless)
            .accessibilityLabel("Dismiss")
        }
        .font(.callout)
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .background(.regularMaterial, in: Capsule())
        .overlay(Capsule().strokeBorder(.separator))
        .shadow(color: .black.opacity(0.18), radius: 12, y: 4)
        .transition(.move(edge: .bottom).combined(with: .opacity))
        .accessibilityElement(children: .contain)
    }
}

// MARK: - Banners

/// Shown when the internet or DNS isn't working, or a Wi-Fi sign-in page is in the way.
struct HealthBanner: View {
    @Environment(AppModel.self) private var model
    var compact = false

    var body: some View {
        let status = model.health.status
        if status.isProblem {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: symbol(status)).font(compact ? .title3 : .title2).foregroundStyle(tint(status))
                VStack(alignment: .leading, spacing: 3) {
                    Text(title(status)).font(compact ? .callout.weight(.semibold) : .headline)
                    if !compact {
                        Text(detail(status)).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    }
                }
                Spacer()
                VStack(alignment: .trailing, spacing: 6) {
                    switch status {
                    case .argusBlockingDNS:
                        Button("Pause 5 Minutes") { Task { await model.pause(minutes: 5) } }
                            .buttonStyle(.borderedProminent).tint(.orange)
                        Button("Troubleshoot") { model.troubleshoot(appPath: nil) }
                    case .captivePortal:
                        Button("Open Sign-In Page") {
                            if let url = URL(string: "http://captive.apple.com") { NSWorkspace.shared.open(url) }
                        }
                        .buttonStyle(.borderedProminent)
                    default:
                        Button("Check Again") { Task { await model.checkHealth() } }
                    }
                }
                .controlSize(compact ? .small : .regular)
            }
            .padding(compact ? 10 : 14)
            .background(tint(status).opacity(0.1), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        }
    }

    private func symbol(_ status: HealthMonitor.Status) -> String {
        switch status {
        case .captivePortal: "wifi.exclamationmark"
        case .argusBlockingDNS: "exclamationmark.shield.fill"
        default: "network.slash"
        }
    }

    private func tint(_ status: HealthMonitor.Status) -> Color { status == .captivePortal ? .accentColor : .orange }

    private func title(_ status: HealthMonitor.Status) -> String {
        switch status {
        case .argusBlockingDNS: "Argus may be blocking your internet"
        case .captivePortal: "This Wi-Fi network wants you to sign in"
        case .dnsFailing: "Your Mac can't look up websites"
        case .offline: "Your Mac can't reach the internet"
        default: ""
        }
    }

    private func detail(_ status: HealthMonitor.Status) -> String {
        switch status {
        case .argusBlockingDNS: "DNS lookups are failing and Argus blocked DNS traffic in the last few minutes, so websites may not load."
        case .captivePortal: "Sign in on the network's page. Argus pauses protection for a few minutes while you do (you can change this in Settings)."
        case .dnsFailing: "Name lookups are failing, but Argus hasn't blocked any DNS traffic. The network or its DNS server is likely the cause."
        case .offline: "Websites don't answer. This doesn't look like Argus's doing; check the network connection."
        default: ""
        }
    }
}

/// While the learning period runs: what it does, when it ends, and the way out.
struct LearningBanner: View {
    @Environment(AppModel.self) private var model
    var compact = false

    var body: some View {
        if let until = model.learningUntil {
            HStack(spacing: 10) {
                Image(systemName: "graduationcap.fill").font(compact ? .title3 : .title2).foregroundStyle(.tint)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Learning what your apps do").font(compact ? .callout.weight(.semibold) : .headline)
                    Text("No alerts until \(until.formatted(date: .abbreviated, time: .shortened)). \(model.reviewItems.count) app\(model.reviewItems.count == 1 ? "" : "s") to review so far.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button("Review Now") { model.showReview = true }
                    .buttonStyle(.borderedProminent)
                    .controlSize(compact ? .small : .regular)
            }
            .padding(compact ? 10 : 14)
            .background(Color.accentColor.opacity(0.1), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        }
    }
}
