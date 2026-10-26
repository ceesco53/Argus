import ArgusKit
import Charts
import SwiftUI

/// "Your week with Argus": what was blocked, by whom, and what's new.
struct DigestView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var days = 7
    @State private var digest: Digest?

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(days == 7 ? "Your week with Argus" : "Your month with Argus").font(.title2.weight(.semibold))
                    if let digest, let first = digest.days.first {
                        Text("\(first.day) to \(digest.days.last?.day ?? first.day)").font(.caption).foregroundStyle(.secondary)
                    }
                }
                Spacer()
                Picker("Period", selection: $days) {
                    Text("7 Days").tag(7)
                    Text("30 Days").tag(30)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 180)
            }
            .padding(20)
            Divider()
            ScrollView {
                if let digest { content(digest) } else { ProgressView().padding(60) }
            }
            Divider()
            HStack {
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
            .padding(14)
        }
        .frame(width: 720, height: 680)
        .task(id: days) { digest = await model.digest(days: days) }
    }

    private func content(_ digest: Digest) -> some View {
        VStack(alignment: .leading, spacing: 18) {
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 150), spacing: 14)], spacing: 14) {
                StatTile(title: "Connections", value: digest.connections.formatted(), symbol: "point.3.connected.trianglepath.dotted")
                StatTile(title: "Blocked", value: digest.blocked.formatted(), symbol: "hand.raised.fill", tint: .denied,
                         footnote: digest.blockedByLists > 0 ? "\(digest.blockedByLists.formatted()) by blocklists" : nil)
                StatTile(title: "Data", value: Formatting.bytes(digest.bytesIn + digest.bytesOut), symbol: "arrow.up.arrow.down.circle.fill",
                         tint: .incoming, footnote: "↓ \(Formatting.bytes(digest.bytesIn))  ↑ \(Formatting.bytes(digest.bytesOut))")
                StatTile(title: "New apps", value: digest.newApps.count.formatted(), symbol: "sparkles", tint: .orange)
            }
            VStack(alignment: .leading, spacing: 10) {
                CardHeader(title: "Day by day", symbol: "chart.bar.fill")
                Chart(digest.days, id: \.day) { day in
                    BarMark(x: .value("Day", shortDay(day.day)), y: .value("Allowed", day.connections - day.blocked))
                        .foregroundStyle(by: .value("Kind", "Allowed"))
                    BarMark(x: .value("Day", shortDay(day.day)), y: .value("Blocked", day.blocked))
                        .foregroundStyle(by: .value("Kind", "Blocked"))
                }
                .chartForegroundStyleScale(["Allowed": Color.allowed, "Blocked": Color.denied])
                .frame(height: 180)
                .accessibilityLabel("Connections per day: \(digest.connections) total, \(digest.blocked) blocked")
            }
            .card()
            HStack(alignment: .top, spacing: 14) {
                ranking("Most blocked servers", symbol: "globe", digest.topBlockedDomains)
                ranking("Most blocked apps", symbol: "app.badge", digest.topBlockedApps)
            }
            if !digest.newApps.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    CardHeader(title: "Apps that used the network for the first time", symbol: "sparkles")
                    Text(digest.newApps.joined(separator: ", ")).foregroundStyle(.secondary)
                    Button("Review Them") {
                        dismiss()
                        model.showReview = true
                    }
                    .buttonStyle(.link)
                }
                .card()
            }
        }
        .padding(20)
    }

    private func ranking(_ title: String, symbol: String, _ entries: [NamedCount]) -> some View {
        let maximum = Double(entries.first?.count ?? 1)
        return VStack(alignment: .leading, spacing: 8) {
            CardHeader(title: title, symbol: symbol)
            if entries.isEmpty { Text("Nothing blocked.").foregroundStyle(.secondary) }
            ForEach(entries) { entry in
                VStack(alignment: .leading, spacing: 3) {
                    HStack {
                        Text(entry.name).lineLimit(1).truncationMode(.middle)
                        Spacer()
                        Text(entry.count.formatted()).font(.callout.monospacedDigit()).foregroundStyle(.secondary)
                    }
                    GeometryReader { geometry in
                        Capsule().fill(Color.denied.opacity(0.6))
                            .frame(width: max(3, geometry.size.width * Double(entry.count) / maximum))
                    }
                    .frame(height: 4)
                }
                .accessibilityElement(children: .combine)
            }
        }
        .card()
    }

    private func shortDay(_ key: String) -> String {
        let parts = key.split(separator: "-")
        return parts.count == 3 ? "\(Int(parts[1]) ?? 0)/\(Int(parts[2]) ?? 0)" : key
    }
}

/// The Overview's "This week" summary.
struct ThisWeekCard: View {
    @Environment(AppModel.self) private var model
    @State private var digest: Digest?

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            CardHeader(title: "This week", symbol: "calendar") {
                Button("Open Report") { model.showDigest = true }.buttonStyle(.link)
            }
            if let digest {
                HStack(spacing: 24) {
                    metric(digest.blocked.formatted(), "blocked", .denied)
                    metric(digest.blockedByLists.formatted(), "by blocklists", .orange)
                    metric(digest.newApps.count.formatted(), "new apps", .accentColor)
                    if let top = digest.topBlockedDomains.first {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(top.name).font(.headline).lineLimit(1)
                            Text("blocked most often").font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    Spacer()
                }
            } else {
                Text("Gathering…").foregroundStyle(.secondary)
            }
        }
        .card()
        .task {
            while !Task.isCancelled {
                digest = await model.digest(days: 7) ?? digest
                // Until the engine answers (it may still be connecting), ask again soon.
                try? await Task.sleep(for: .seconds(digest == nil ? 3 : 300))
            }
        }
    }

    private func metric(_ value: String, _ label: String, _ color: Color) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(value).font(.title3.weight(.semibold).monospacedDigit()).foregroundStyle(color)
            Text(label).font(.caption).foregroundStyle(.secondary)
        }
        .accessibilityElement(children: .combine)
    }
}
