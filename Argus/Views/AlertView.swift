import ArgusKit
import Combine
import SwiftUI

/// Shown in the floating panel while a connection is held for a decision.
struct AlertView: View {
    @Environment(AppModel.self) private var model
    /// Reports the alert's natural height so the window can match it.
    var onHeightChange: (CGFloat) -> Void = { _ in }

    var body: some View {
        Group {
            if let alert = model.focusedAlert {
                AlertContent(alert: alert, waiting: model.alerts.count - 1)
                    .id(alert.id) // fresh choices for every alert
            } else {
                Color.clear.frame(width: 470, height: 1)
            }
        }
        .fixedSize(horizontal: false, vertical: true)
        .onGeometryChange(for: CGFloat.self) { $0.size.height } action: { onHeightChange($0) }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
    }
}

private struct AlertContent: View {
    let alert: ConnectionAlert
    let waiting: Int

    @Environment(AppModel.self) private var model
    @AppStorage("alertDefaultDuration") private var defaultDuration = "forever"
    @State private var server: ServerChoice = .host
    @State private var port: AlertDecision.PortScope = .thisPort
    @State private var process: AlertDecision.ProcessScope = .thisProcess
    @State private var duration: AlertDecision.Duration = .forever
    @State private var onlyMe = false
    @State private var onlyThisProfile = false
    @State private var showOptions = false
    @State private var showReasons = false
    @State private var answerOthers = false
    @State private var now = Date()
    private let ticker = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    enum ServerChoice: Hashable { case host, domain, any }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            header
            if let advice = alert.advice {
                AdviceBanner(advice: advice, showReasons: $showReasons)
            }
            if let warning = alert.signatureWarning {
                Label(warning + " Be careful allowing it.", systemImage: "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(.orange)
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 8))
            }
            choices
            details
            if !otherAlertsFromApp.isEmpty {
                Toggle("Answer \(alert.process.name)'s \(otherAlertsFromApp.count) other waiting alert\(otherAlertsFromApp.count == 1 ? "" : "s") the same way",
                       isOn: $answerOthers)
                    .toggleStyle(.checkbox)
                    .font(.callout)
            }
            footer
            if waiting > 0 { WaitingAlerts(current: alert) }
        }
        .padding(22)
        .frame(width: 470)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).strokeBorder(.separator.opacity(0.8)))
        .onAppear {
            duration = Self.duration(from: defaultDuration)
            if alert.hostname == nil { server = .host }
            if alert.advice?.suggestedDomain != nil, domainOption != nil { server = .domain }
            Task { await model.alertShown(alert) }
        }
        .onReceive(ticker) { now = $0 }
    }

    // MARK: Sections

    private var header: some View {
        HStack(alignment: .top, spacing: 14) {
            AppIconView(identity: alert.process, size: 56)
                .overlay(alignment: .bottomTrailing) {
                    Image(systemName: alert.direction == .incoming ? "arrow.down.circle.fill" : "arrow.up.right.circle.fill")
                        .font(.title3)
                        .foregroundStyle(.white, Color.accentColor)
                        .offset(x: 4, y: 4)
                }
            VStack(alignment: .leading, spacing: 4) {
                Text("**\(alert.process.name)** wants to \(alert.direction == .incoming ? "accept a connection from" : "connect to")")
                    .font(.callout)
                Text(alert.remoteDisplay)
                    .font(.title2.weight(.bold))
                    .lineLimit(2)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
                HStack(spacing: 8) {
                    Text(Formatting.endpoint(port: alert.port, proto: alert.proto))
                    if alert.pendingConnections > 1 {
                        Text("· \(alert.pendingConnections) attempts")
                    }
                    if let country = model.geo.country(for: alert.address) {
                        Text("·")
                        CountryLabel(country: country)
                    }
                }
                .font(.caption)
                .foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
            if waiting > 0 {
                Pill(text: "+\(waiting) more", tint: .orange)
            }
        }
    }

    private var choices: some View {
        Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 10) {
            GridRow {
                Text("Server").foregroundStyle(.secondary).gridColumnAlignment(.trailing)
                Picker("Server", selection: $server) {
                    Text("Only \(alert.remoteDisplay)").tag(ServerChoice.host)
                    if let domain = domainOption {
                        Text("\(domain) and its subdomains").tag(ServerChoice.domain)
                    }
                    Text("Any server").tag(ServerChoice.any)
                }
                .labelsHidden()
            }
            GridRow {
                Text("Port").foregroundStyle(.secondary)
                Picker("Port", selection: $port) {
                    Text("Only \(Formatting.endpoint(port: alert.port, proto: alert.proto))").tag(AlertDecision.PortScope.thisPort)
                    Text("Any port").tag(AlertDecision.PortScope.anyPort)
                }
                .labelsHidden()
            }
            GridRow {
                Text("Remember").foregroundStyle(.secondary)
                Picker("Remember", selection: $duration) {
                    ForEach(AlertDecision.Duration.allCases, id: \.self) { option in
                        Text(option.displayName).tag(option)
                    }
                }
                .labelsHidden()
            }
            if showOptions {
                GridRow {
                    Text("Program").foregroundStyle(.secondary)
                    Picker("Program", selection: $process) {
                        Text("Only \(alert.process.name)").tag(AlertDecision.ProcessScope.thisProcess)
                        Text("Any program").tag(AlertDecision.ProcessScope.anyProcess)
                    }
                    .labelsHidden()
                }
                GridRow {
                    Text("Applies to").foregroundStyle(.secondary)
                    VStack(alignment: .leading, spacing: 4) {
                        Toggle("Only \(SystemInfo.userName(for: alert.userID))", isOn: $onlyMe)
                        if let profile = model.state.activeProfile {
                            Toggle("Only in the “\(profile.name)” profile", isOn: $onlyThisProfile)
                        }
                    }
                }
            }
        }
        .controlSize(.regular)
    }

    private var details: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 10) {
                SignatureBadge(kind: alert.process.signature)
                if let via = alert.via {
                    Text("via \(via.name)").font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Button(showOptions ? "Fewer Options" : "More Options") {
                    withAnimation(.snappy) { showOptions.toggle() }
                }
                .buttonStyle(.link)
                .font(.caption)
                if let host = alert.hostname, let url = researchURL(for: host) {
                    Link("What is this?", destination: url).font(.caption)
                }
            }
            Text(alert.process.path)
                .font(.caption2.monospaced())
                .foregroundStyle(.tertiary)
                .lineLimit(1)
                .truncationMode(.middle)
                .textSelection(.enabled)
        }
    }

    private var footer: some View {
        HStack(spacing: 10) {
            if let deadline = alert.deadline {
                let remaining = max(0, deadline.timeIntervalSince(now))
                let total = max(1, deadline.timeIntervalSince(alert.createdAt))
                VStack(alignment: .leading, spacing: 3) {
                    Text("\(timeoutAction == .allow ? "Allowing" : "Denying") once in \(Int(remaining))s")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .monospacedDigit()
                    ProgressView(value: remaining, total: total)
                        .progressViewStyle(.linear)
                        .frame(width: 120)
                        .tint(.secondary)
                }
            }
            Spacer()
            answerButton(.deny)
            answerButton(.allow)
        }
    }

    /// The suggested answer is the prominent, Return-key button; Allow is the default otherwise.
    @ViewBuilder
    private func answerButton(_ action: RuleAction) -> some View {
        let preferred = (alert.advice?.suggestion ?? .allow) == action
        let button = Button(role: action == .deny ? .destructive : nil) {
            answer(action)
        } label: {
            Text(action.displayName).frame(minWidth: 70)
        }
        .controlSize(.large)
        if preferred {
            button
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .tint(action == .deny ? Color.denied : Color.accentColor)
        } else {
            button.keyboardShortcut(action == .deny ? .delete : .return, modifiers: .command)
        }
    }

    // MARK: Derived

    /// The whole-domain option: the advisor's domain (e.g. a listed tracker) or the registrable one.
    private var domainOption: String? {
        let domain = alert.advice?.suggestedDomain ?? alert.suggestedDomain
        return domain == alert.hostname ? nil : domain
    }

    private var otherAlertsFromApp: [ConnectionAlert] {
        model.alerts.filter { $0.id != alert.id && $0.process.path == alert.process.path }
    }

    /// What happens if nobody answers in time.
    private var timeoutAction: RuleAction {
        let settings = model.state.settings
        if settings.alertTimeoutFollowsAdvice, let advice = alert.advice, advice.isConfident, let suggestion = advice.suggestion {
            return suggestion
        }
        return settings.alertTimeoutAction
    }

    // MARK: Answering

    private func answer(_ action: RuleAction) {
        let remote: AlertDecision.RemoteScope = switch server {
        case .host: alert.hostname == nil ? .address : .host
        case .domain: .domain(domainOption ?? alert.hostname ?? "")
        case .any: .any
        }
        let decision = AlertDecision(
            action: action, processScope: process, remoteScope: remote, portScope: port, duration: duration,
            allUsers: !onlyMe, activeProfileOnly: onlyThisProfile)
        let others = answerOthers ? otherAlertsFromApp : []
        Task { await model.resolve(alert, with: decision, alsoAnswering: others) }
    }

    static func duration(from key: String) -> AlertDecision.Duration {
        switch key {
        case "once": .once
        case "untilQuit": .untilQuit
        case "untilRestart": .untilRestart
        default: Int(key).map(AlertDecision.Duration.minutes) ?? .forever
        }
    }
}

/// Argus's suggestion for the alert, with the reasons behind it on request.
private struct AdviceBanner: View {
    let advice: ConnectionAdvice
    @Binding var showReasons: Bool

    var body: some View {
        let (symbol, tint) = style
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: symbol)
                    .font(.title3)
                    .foregroundStyle(tint)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(.callout.weight(.semibold))
                    if let headline = advice.headline {
                        Text(headline)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                Spacer(minLength: 4)
                if advice.reasons.count > 1 {
                    Button(showReasons ? "Less" : "Why?") { withAnimation(.snappy) { showReasons.toggle() } }
                        .buttonStyle(.link)
                        .font(.caption)
                }
            }
            if showReasons {
                VStack(alignment: .leading, spacing: 5) {
                    ForEach(advice.reasons, id: \.self) { reason in
                        Label {
                            Text(reason.text).font(.caption).fixedSize(horizontal: false, vertical: true)
                        } icon: {
                            Image(systemName: reason.leansTo == .allow ? "plus.circle.fill" : reason.leansTo == .deny ? "minus.circle.fill" : "info.circle")
                                .foregroundStyle(reason.leansTo == .allow ? Color.allowed : reason.leansTo == .deny ? Color.denied : .secondary)
                        }
                    }
                }
                .padding(.leading, 30)
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(tint.opacity(0.12), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .accessibilityElement(children: .combine)
    }

    private var title: String {
        guard let suggestion = advice.suggestion else { return "No clear suggestion: the signals point both ways" }
        let verb = suggestion == .allow ? "allowing" : "denying"
        switch advice.strength {
        case .strong: return "Argus strongly suggests \(verb)"
        case .moderate: return "Argus suggests \(verb)"
        case .weak: return "Argus leans towards \(verb)"
        }
    }

    private var style: (String, Color) {
        switch advice.suggestion {
        case .deny where advice.strength == .strong: ("exclamationmark.octagon.fill", .denied)
        case .deny: ("hand.raised.fill", .denied)
        case .allow: ("hand.thumbsup.fill", .allowed)
        case nil: ("questionmark.circle.fill", .secondary)
        }
    }
}

/// The other alerts, grouped by app, with one-click answers for a whole app.
private struct WaitingAlerts: View {
    @Environment(AppModel.self) private var model
    let current: ConnectionAlert

    var body: some View {
        let others = model.alerts.filter { $0.id != current.id }
        let groups = Dictionary(grouping: others, by: \.process.path)
            .map { (path: $0.key, alerts: $0.value) }
            .sorted { $0.alerts.count > $1.alerts.count }
        VStack(alignment: .leading, spacing: 8) {
            Divider()
            HStack {
                Text("Also waiting").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                Spacer()
                if others.count >= 3, model.learningUntil == nil {
                    Button("Too many alerts? Learn quietly for 3 days") { Task { await model.startLearning(days: 3) } }
                        .buttonStyle(.link)
                        .font(.caption)
                        .help("Allows unknown connections without asking for 3 days, then lets you review every app at once")
                }
            }
            ForEach(groups.prefix(4), id: \.path) { group in
                let process = group.alerts[0].process
                let hosts = group.alerts.map(\.remoteDisplay)
                HStack(spacing: 8) {
                    AppIconView(identity: process, size: 22)
                    VStack(alignment: .leading, spacing: 0) {
                        Text("\(process.name) · \(group.alerts.count)").font(.callout.weight(.medium))
                        Text(hosts.joined(separator: ", ")).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                    }
                    Spacer(minLength: 6)
                    Button("Show") { model.focusedAlertID = group.alerts[0].id }
                    Menu("Answer All") {
                        Button("Allow These \(hosts.count) Servers") { Task { await model.answerAll(from: group.path, action: .allow, anywhere: false) } }
                        Button("Deny These \(hosts.count) Servers") { Task { await model.answerAll(from: group.path, action: .deny, anywhere: false) } }
                        Divider()
                        Button("Allow \(process.name) to Connect Anywhere") { Task { await model.answerAll(from: group.path, action: .allow, anywhere: true) } }
                        Button("Block \(process.name) Everywhere") { Task { await model.answerAll(from: group.path, action: .deny, anywhere: true) } }
                    }
                    .fixedSize()
                }
                .controlSize(.small)
            }
            if groups.count > 4 {
                Text("and \(groups.count - 4) more apps").font(.caption).foregroundStyle(.tertiary)
            }
        }
    }
}
