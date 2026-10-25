import ArgusKit
import Charts
import SwiftUI

struct OverviewView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                HeroCard()
                PausedBanner()
                if model.engine == .monitor { MonitorModeBanner() }
                if let network = model.networkPrompt { NetworkPromptView(network: network) }
                if !model.bpfUsers.isEmpty || !model.warningEvents.isEmpty { SecurityNoticeCard() }
                stats
                TrafficCard()
                HStack(alignment: .top, spacing: 18) {
                    TopAppsCard()
                    RecentlyBlockedCard()
                }
            }
            .padding(24)
        }
        .navigationTitle("Overview")
    }

    private var stats: some View {
        let today = model.today
        return LazyVGrid(columns: [GridItem(.adaptive(minimum: 170), spacing: 18)], spacing: 18) {
            StatTile(title: "Connections today", value: today.connections.formatted(), symbol: "point.3.connected.trianglepath.dotted")
            StatTile(title: model.isEnforcing ? "Blocked today" : "Would be blocked today", value: today.blocked.formatted(),
                     symbol: "hand.raised.fill", tint: .denied,
                     footnote: today.blockedByLists > 0 ? "\(today.blockedByLists.formatted()) by blocklists" : nil)
            StatTile(title: "Received today", value: Formatting.bytes(today.bytesIn), symbol: "arrow.down.circle.fill", tint: .incoming)
            StatTile(title: "Sent today", value: Formatting.bytes(today.bytesOut), symbol: "arrow.up.circle.fill", tint: .outgoing)
        }
    }
}

private struct HeroCard: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let settings = model.state.settings
        HStack(spacing: 22) {
            MascotView(asleep: model.isAsleep, size: 128)
                .shadow(color: .accentColor.opacity(0.25), radius: 18, y: 6)
            VStack(alignment: .leading, spacing: 8) {
                Text(model.pausedUntil != nil ? "Argus is resting" : settings.protectionEnabled ? "Argus is watching" : "Argus is asleep")
                    .font(.system(.largeTitle, design: .rounded, weight: .bold))
                Text(subtitle)
                    .font(.title3)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 8) {
                    Pill(text: model.isEnforcing ? "Network filter active" : "Monitor only",
                         symbol: model.isEnforcing ? "checkmark.shield.fill" : "eye",
                         tint: model.isEnforcing ? .allowed : .orange)
                    if let profile = model.state.activeProfile {
                        Pill(text: profile.name, symbol: profile.symbolName)
                    }
                    let lists = model.state.ruleGroups.filter(\.isEnabled).count
                    if lists > 0 {
                        Pill(text: "\(lists) blocklist\(lists == 1 ? "" : "s")", symbol: "shield.lefthalf.filled", tint: .secondary)
                    }
                }
            }
            Spacer(minLength: 0)
            VStack(alignment: .trailing, spacing: 12) {
                HStack(spacing: 12) {
                    PauseMenu {
                        Label(model.pausedUntil == nil ? "Pause" : "Paused", systemImage: "pause.circle")
                    }
                    .fixedSize()
                    Toggle("Protection", isOn: Binding(get: { settings.protectionEnabled },
                                                       set: { value in Task { await model.setProtection(value) } }))
                        .toggleStyle(.switch)
                        .controlSize(.large)
                }
                Picker("New connections", selection: Binding(get: { settings.mode }, set: { mode in Task { await model.setMode(mode) } })) {
                    ForEach(FilterMode.allCases, id: \.self) { Text($0.displayName).tag($0) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 300)
                .disabled(!settings.protectionEnabled)
                Text(model.state.effectiveMode.explanation)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.trailing)
                    .frame(width: 300, alignment: .trailing)
            }
        }
        .padding(22)
        .background(
            LinearGradient(colors: [Color.accentColor.opacity(0.16), Color.allowed.opacity(0.08)], startPoint: .topLeading, endPoint: .bottomTrailing),
            in: RoundedRectangle(cornerRadius: 18, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 18, style: .continuous).strokeBorder(.separator.opacity(0.6)))
    }

    private var subtitle: String {
        guard model.state.settings.protectionEnabled else {
            return "Protection is off. Every connection is allowed and nothing is filtered."
        }
        if model.pausedUntil != nil {
            return "Protection is paused. Everything is allowed until it resumes."
        }
        let apps = model.processes.values.filter { $0.activeFlows > 0 }.count
        let active = apps == 0 ? "No apps are talking right now." : "\(apps) app\(apps == 1 ? " is" : "s are") talking to the internet right now."
        return "\(active) \(model.state.rules.count) rules keep watch."
    }
}

private struct TrafficCard: View {
    @Environment(AppModel.self) private var model
    @State private var range: Range = .live
    @State private var history: [TrafficBucket] = []

    enum Range: String, CaseIterable, Identifiable {
        case live = "Live", hour = "Hour", day = "Day", month = "Month"
        var id: String { rawValue }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            CardHeader(title: "Traffic", symbol: "chart.xyaxis.line") {
                ChartLegend()
                Picker("Range", selection: $range) {
                    ForEach(Range.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 240)
            }
            if range == .live {
                HStack(alignment: .firstTextBaseline) {
                    Text(Formatting.rate(model.currentRate.total))
                        .font(.system(.title2, design: .rounded, weight: .semibold))
                        .monospacedDigit()
                    RateLabel(rate: model.currentRate)
                }
            }
            TrafficChart(buckets: range == .live ? model.recentTraffic : history, resolution: resolution, height: 180)
        }
        .card()
        .task(id: range) { await load() }
    }

    private var resolution: TrafficResolution {
        switch range {
        case .live: .second
        case .hour, .day: .minute
        case .month: .hour
        }
    }

    private func load() async {
        guard range != .live else { return }
        let since: Date = switch range {
        case .live: Date()
        case .hour: Date().addingTimeInterval(-3600)
        case .day: Date().addingTimeInterval(-86_400)
        case .month: Date().addingTimeInterval(-30 * 86_400)
        }
        while !Task.isCancelled {
            if case .traffic(let buckets)? = await model.perform(.getTraffic(TrafficQuery(resolution: resolution, since: since))) {
                history = range == .day ? Self.aggregate(buckets, every: 10) : buckets
            }
            try? await Task.sleep(for: .seconds(range == .hour ? 10 : 60))
        }
    }

    /// Keeps day charts readable by summing neighbouring minutes.
    static func aggregate(_ buckets: [TrafficBucket], every n: Int) -> [TrafficBucket] {
        stride(from: 0, to: buckets.count, by: n).map { start in
            let slice = buckets[start..<min(start + n, buckets.count)]
            return TrafficBucket(start: slice.first!.start, bytesIn: slice.reduce(0) { $0 + $1.bytesIn } / UInt64(slice.count),
                                 bytesOut: slice.reduce(0) { $0 + $1.bytesOut } / UInt64(slice.count))
        }
    }
}

private struct TopAppsCard: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let top = model.processes.values.sorted { $0.totalBytes > $1.totalBytes }.prefix(6)
        let maximum = max(top.first?.totalBytes ?? 1, 1)
        VStack(alignment: .leading, spacing: 12) {
            CardHeader(title: "Busiest apps", symbol: "chart.bar.fill") {
                Button("Show All") { model.section = .monitor }.buttonStyle(.link)
            }
            if top.isEmpty {
                Text("Nothing has used the network yet.").foregroundStyle(.secondary)
            }
            ForEach(Array(top)) { process in
                Button {
                    model.selectedProcessPath = process.id
                    model.section = .monitor
                } label: {
                    HStack(spacing: 10) {
                        AppIconView(identity: process.identity, size: 26)
                        VStack(alignment: .leading, spacing: 3) {
                            HStack {
                                Text(process.identity.name).lineLimit(1)
                                Spacer()
                                Text(Formatting.bytes(process.totalBytes)).font(.callout.monospacedDigit()).foregroundStyle(.secondary)
                            }
                            GeometryReader { geometry in
                                let inWidth = geometry.size.width * CGFloat(Double(process.bytesIn) / Double(maximum))
                                let outWidth = geometry.size.width * CGFloat(Double(process.bytesOut) / Double(maximum))
                                HStack(spacing: 1) {
                                    Capsule().fill(Color.incoming).frame(width: max(inWidth, 2))
                                    Capsule().fill(Color.outgoing).frame(width: max(outWidth, 2))
                                    Spacer(minLength: 0)
                                }
                            }
                            .frame(height: 5)
                        }
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
        }
        .card()
    }
}

private struct RecentlyBlockedCard: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let blocked = model.recentlyBlocked.prefix(8)
        VStack(alignment: .leading, spacing: 12) {
            CardHeader(title: model.isEnforcing ? "Recently blocked" : "Would have been blocked", symbol: "hand.raised.fill")
            if blocked.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Nothing blocked recently.").foregroundStyle(.secondary)
                    if model.state.ruleGroups.isEmpty {
                        Button("Add a blocklist to stop ads and trackers") { model.section = .blocklists }.buttonStyle(.link)
                    }
                }
            }
            ForEach(Array(blocked)) { entry in
                BlockedRow(entry: entry, model: model)
            }
        }
        .card()
    }
}

private struct SecurityNoticeCard: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            CardHeader(title: "Needs your attention", symbol: "exclamationmark.shield.fill") {
                Button("Review") { model.section = .security }.buttonStyle(.link)
            }
            ForEach(model.bpfUsers) { user in
                Label("\(user.name) can read all network traffic (\(user.device))", systemImage: "antenna.radiowaves.left.and.right")
                    .foregroundStyle(.orange)
            }
            ForEach(model.warningEvents.prefix(3)) { event in
                Label(event.title, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange)
            }
        }
        .card()
    }
}
