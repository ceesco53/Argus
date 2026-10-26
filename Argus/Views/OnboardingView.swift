import ArgusKit
import ServiceManagement
import SwiftUI

/// First-run guide: meet Argus, set up the filter, pick a mode and some blocklists.
struct OnboardingView: View {
    @Environment(AppModel.self) private var model
    @AppStorage("hasCompletedOnboarding") private var hasCompletedOnboarding = false
    let onFinish: () -> Void

    @State private var page = 0
    @State private var mode: FilterMode = .alert
    @State private var learnFirst = true
    @State private var chosenLists: Set<String> = Set(BlocklistCatalog.entries.filter(\.isRecommended).map(\.id))
    @State private var launchAtLogin = true
    @State private var downloadLocations = true

    private let pageCount = 5

    var body: some View {
        VStack(spacing: 0) {
            Group {
                switch page {
                case 0: welcome
                case 1: filterPage
                case 2: modePage
                case 3: blocklistPage
                default: donePage
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .padding(32)
            .transition(.asymmetric(insertion: .move(edge: .trailing).combined(with: .opacity), removal: .move(edge: .leading).combined(with: .opacity)))
            .id(page)

            Divider()
            HStack {
                HStack(spacing: 6) {
                    ForEach(0..<pageCount, id: \.self) { index in
                        Circle().fill(index == page ? Color.accentColor : Color.secondary.opacity(0.3)).frame(width: 7, height: 7)
                    }
                }
                Spacer()
                if page > 0 {
                    Button("Back") { withAnimation(.snappy) { page -= 1 } }
                }
                Button(page == pageCount - 1 ? "Start Watching" : "Continue") { advance() }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
            }
            .padding(20)
        }
        .frame(width: 680, height: 560)
    }

    private func advance() {
        switch page {
        case 2:
            Task {
                if learnFirst { await model.startLearning(days: 3) } else { await model.setMode(mode) }
            }
        case 3:
            let existing = Set(model.state.ruleGroups.compactMap(\.catalogID))
            for entry in BlocklistCatalog.entries where chosenLists.contains(entry.id) && !existing.contains(entry.id) {
                Task { await model.subscribe(to: entry) }
            }
            if downloadLocations, !model.geo.isReady { Task { await model.geo.update() } }
        case pageCount - 1:
            if launchAtLogin { try? SMAppService.mainApp.register() } else { try? SMAppService.mainApp.unregister() }
            hasCompletedOnboarding = true
            onFinish()
            return
        default:
            break
        }
        withAnimation(.snappy) { page += 1 }
    }

    // MARK: Pages

    private var welcome: some View {
        VStack(spacing: 18) {
            MascotView(size: 210)
                .shadow(color: .accentColor.opacity(0.3), radius: 24, y: 8)
            Text("Meet Argus").font(.system(size: 40, weight: .bold, design: .rounded))
            Text("In Greek myth, Argus Panoptes had a hundred eyes and never slept. This one watches your Mac's network instead: every connection every app makes, and whether it should be allowed.")
                .font(.title3)
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .frame(maxWidth: 520)
        }
    }

    private var filterPage: some View {
        VStack(alignment: .leading, spacing: 18) {
            pageHeader("network.badge.shield.half.filled", "The network filter", "To hold a connection until you decide, Argus installs a network filter that macOS runs alongside the system.")
            switch model.filter.status {
            case .unavailable:
                infoBox("eye", .orange, "Monitor mode",
                        "This copy of Argus wasn't built with Apple's Network Extension entitlement, so it can't install the filter. It will still show you every connection, map where data goes, and keep your rules and blocklists ready for when a signed build installs the filter.")
            case .enabled:
                infoBox("checkmark.shield.fill", .allowed, "The filter is installed", "Argus is ready to protect this Mac.")
            case .awaitingApproval:
                infoBox("hand.raised.fill", .orange, "One more step",
                        "macOS needs your permission. Open System Settings › General › Login Items & Extensions › Network Extensions and turn on Argus.")
                Button("Open System Settings") {
                    NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension")!)
                }
            case .installing, .checking:
                ProgressView("Installing…")
            case .failed(let message):
                infoBox("exclamationmark.triangle.fill", .orange, "That didn't work", message)
                Button("Try Again") { model.filter.install() }
            case .notInstalled, .disabled:
                infoBox("lock.shield", .accentColor, "Your privacy stays on this Mac",
                        "The filter only decides allow or deny. It never sends your traffic anywhere, and you can remove it at any time in Settings.")
                Button("Install Network Filter") { model.filter.install() }
                    .buttonStyle(.borderedProminent)
            }
            Spacer()
        }
    }

    private var modePage: some View {
        VStack(alignment: .leading, spacing: 18) {
            pageHeader("bell.badge", "When an app tries something new", "You can change this at any time from the menu bar.")
            VStack(spacing: 10) {
                learnCard
                modeCard(.alert, "Ask me from the start", "Argus holds each new connection and asks. Most private, but expect a lot of questions on the first day.")
                modeCard(.silentAllow, "Allow, and let me review later", "Nothing is interrupted. Unknown connections are allowed and marked so you can make rules later.")
                modeCard(.silentDeny, "Deny anything I haven't allowed", "Lockdown. Only Apple software and connections you've explicitly allowed get through.")
            }
            Spacer()
        }
    }

    private var learnCard: some View {
        Button {
            learnFirst = true
        } label: {
            HStack(spacing: 14) {
                Image(systemName: "graduationcap")
                    .font(.title2)
                    .foregroundStyle(.tint)
                    .frame(width: 36)
                VStack(alignment: .leading, spacing: 3) {
                    HStack {
                        Text("Learn for 3 days, then ask me").font(.headline)
                        Pill(text: "Recommended", tint: .allowed)
                    }
                    Text("Argus quietly records what your apps do, then you review them all at once. After that it asks about anything new.")
                        .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                Spacer()
                Image(systemName: learnFirst ? "checkmark.circle.fill" : "circle")
                    .font(.title2)
                    .foregroundStyle(learnFirst ? Color.accentColor : .secondary)
            }
            .padding(14)
            .background(learnFirst ? Color.accentColor.opacity(0.1) : Color.clear, in: RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(learnFirst ? Color.accentColor : Color.secondary.opacity(0.25)))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(learnFirst ? .isSelected : [])
    }

    private func modeCard(_ value: FilterMode, _ title: String, _ detail: String, recommended: Bool = false) -> some View {
        let selected = !learnFirst && mode == value
        return Button {
            learnFirst = false
            mode = value
        } label: {
            HStack(spacing: 14) {
                Image(systemName: value.symbolName)
                    .font(.title2)
                    .foregroundStyle(.tint)
                    .frame(width: 36)
                VStack(alignment: .leading, spacing: 3) {
                    HStack {
                        Text(title).font(.headline)
                        if recommended { Pill(text: "Recommended", tint: .allowed) }
                    }
                    Text(detail).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                Spacer()
                Image(systemName: selected ? "checkmark.circle.fill" : "circle")
                    .font(.title2)
                    .foregroundStyle(selected ? Color.accentColor : .secondary)
            }
            .padding(14)
            .background(selected ? Color.accentColor.opacity(0.1) : Color.clear, in: RoundedRectangle(cornerRadius: 12))
            .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(selected ? Color.accentColor : Color.secondary.opacity(0.25)))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private var blocklistPage: some View {
        VStack(alignment: .leading, spacing: 18) {
            pageHeader("shield.lefthalf.filled", "Block ads, trackers and malware", "Community blocklists are kept up to date for you. Pick a couple to start; you can add more later.")
            ScrollView {
                VStack(spacing: 8) {
                    ForEach(BlocklistCatalog.entries.filter { $0.approximateEntries < 500_000 }) { entry in
                        Toggle(isOn: Binding(get: { chosenLists.contains(entry.id) },
                                             set: { if $0 { chosenLists.insert(entry.id) } else { chosenLists.remove(entry.id) } })) {
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(entry.displayName).font(.headline)
                                    Text(entry.summary).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                                }
                                Spacer()
                                if entry.isRecommended { Pill(text: "Recommended", tint: .allowed) }
                            }
                        }
                        .toggleStyle(.checkbox)
                        .padding(10)
                        .background(.quaternary.opacity(0.3), in: RoundedRectangle(cornerRadius: 10))
                    }
                }
            }
            Toggle(isOn: $downloadLocations) {
                Text("Also show where servers are located")
                Text("Downloads about 20 MB of public data from the internet registries. Lookups stay on your Mac.")
            }
            .toggleStyle(.checkbox)
        }
    }

    private var donePage: some View {
        VStack(spacing: 18) {
            ZStack {
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .fill(.quaternary.opacity(0.5))
                    .frame(width: 260, height: 44)
                HStack(spacing: 18) {
                    Image(systemName: "wifi")
                    Image(systemName: "battery.75percent")
                    Image("MenuBarGlyph")
                        .padding(5)
                        .background(Color.accentColor.opacity(0.25), in: RoundedRectangle(cornerRadius: 6))
                    Text("9:41")
                }
                .font(.title3)
            }
            Text("Argus lives in your menu bar").font(.system(size: 30, weight: .bold, design: .rounded))
            Text("Click the three-eyed icon for live traffic, to pause protection or to switch profiles. Alerts appear in a small window in the corner of your screen.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .frame(maxWidth: 500)
            Toggle("Open Argus when I log in", isOn: $launchAtLogin)
                .toggleStyle(.switch)
                .padding(.top, 8)
        }
    }

    private func pageHeader(_ symbol: String, _ title: String, _ subtitle: String) -> some View {
        HStack(alignment: .top, spacing: 16) {
            Image(systemName: symbol)
                .font(.system(size: 30))
                .foregroundStyle(.tint)
                .frame(width: 50, height: 50)
                .background(Color.accentColor.opacity(0.14), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.title.weight(.bold))
                Text(subtitle).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func infoBox(_ symbol: String, _ tint: Color, _ title: String, _ text: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: symbol).font(.title2).foregroundStyle(tint)
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.headline)
                Text(text).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(tint.opacity(0.1), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
    }
}
