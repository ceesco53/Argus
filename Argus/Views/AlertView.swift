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
    @State private var port: PortChoice = .thisPort
    /// What this alert shares with the app's other alerts and rules, when that's wider than its
    /// one server and port. The choices start on it; one found later is offered instead.
    @State private var pattern: AlertPattern?
    @State private var process: AlertDecision.ProcessScope = .thisProcess
    @State private var duration: AlertDecision.Duration = .forever
    @State private var onlyMe = false
    @State private var onlyThisProfile = false
    @State private var showOptions = false
    @State private var showReasons = false
    @State private var answerOthers = false
    @State private var now = Date()
    private let ticker = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    enum ServerChoice: Hashable { case host, domain, network(IPNetwork), any }
    enum PortChoice: Hashable { case thisPort, range(PortRange), anyPort }

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
            let reach = self.reach
            if let pattern = notedPattern {
                PatternNote(headline: headline(for: pattern), detail: detail(of: reach, on: pattern), isApplied: isOn(pattern)) {
                    withAnimation(.snappy) { if isOn(pattern) { narrow(from: pattern) } else { start(on: pattern) } }
                }
            }
            choices
            // Any server on the app's ports is the closer fit; Allow Everywhere would only repeat it.
            if notedPattern?.servers != .any, let allowed = allowedBefore {
                AllowEverywhereOffer(appName: alert.process.name, allowed: allowed) {
                    Task { await model.answerAll(from: alert.process.path, action: .allow, anywhere: true) }
                }
            }
            details
            if notedPattern == nil, let summary = summary(of: reach) {
                Label("\(preferredAction == .allow ? "Allowing" : "Denying") also \(summary).", systemImage: "checkmark.circle")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            let others = otherAlertsFromApp.filter { !reach.alerts.contains($0.id) }
            if !others.isEmpty {
                Toggle("Answer \(alert.process.name)'s \(others.count) other waiting alert\(others.count == 1 ? "" : "s") the same way",
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
            if let domain = domainOption,
               alert.advice?.suggestedDomain != nil || alert.prefersDomain(domain, rules: model.state.rules, waiting: model.alerts) {
                server = .domain
            }
            pattern = alert.pattern(rules: model.state.rules, waiting: model.alerts)
            if let pattern = notedPattern { start(on: pattern) }
            Task { await model.alertShown(alert) }
        }
        .onChange(of: model.alerts.count) {
            // More of the app's alerts arrived while this one was showing. What they share is
            // offered, with a button: the choices never change under the pointer.
            if let fresh = alert.pattern(rules: model.state.rules, waiting: model.alerts), fresh != pattern {
                withAnimation(.snappy) { pattern = fresh }
            }
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
                    ForEach(networkOptions, id: \.self) { network in
                        Text("Any of \(network.familiarDescription)").tag(ServerChoice.network(network))
                    }
                    Text("Any server").tag(ServerChoice.any)
                }
                .labelsHidden()
            }
            GridRow {
                Text("Port").foregroundStyle(.secondary)
                Picker("Port", selection: $port) {
                    Text("Only \(Formatting.port(alert.port, proto: alert.proto))").tag(PortChoice.thisPort)
                    ForEach(portRanges, id: \.self) { range in
                        Text("Ports \(Self.span(range))").tag(PortChoice.range(range))
                    }
                    Text("Any port").tag(PortChoice.anyPort)
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
        let preferred = preferredAction == action
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

    /// How many times this app has been allowed, when that's often enough, and it's never been
    /// denied, to offer allowing it everywhere (a game reaching relay after relay, one IP at a time).
    private var allowedBefore: Int? {
        guard alert.direction == .outgoing else { return nil }
        let (allowed, denied) = alert.answeredBefore(in: model.state.rules)
        return denied == 0 && allowed >= ConnectionAlert.allowEverywhereAfter ? allowed : nil
    }

    private var otherAlertsFromApp: [ConnectionAlert] {
        model.alerts.filter { $0.id != alert.id && $0.process.path == alert.process.path }
    }

    /// The answer the prominent button gives.
    private var preferredAction: RuleAction { alert.advice?.suggestion ?? .allow }

    // MARK: A wider answer

    /// The pattern to start on and explain. A suggestion to deny is about this one server (a
    /// listed address, say), so it isn't widened to the app's others; the choices are still there.
    private var notedPattern: AlertPattern? { alert.advice?.suggestion == .deny ? nil : pattern }

    /// The networks around a nameless server, narrowest first, with the pattern's if it's another
    /// (and the one chosen, should the pattern have moved on from it).
    private var networkOptions: [IPNetwork] {
        var networks = alert.networks
        if case .network(let network)? = pattern?.servers, !networks.contains(network) { networks.append(network) }
        if case .network(let chosen) = server, !networks.contains(chosen) { networks.append(chosen) }
        return networks.sorted { $0.prefixLength > $1.prefixLength }
    }

    /// The pattern's stretch of ports, and the one chosen if that's another.
    private var portRanges: [PortRange] {
        var ranges = [pattern?.ports].compactMap { $0 }
        if case .range(let chosen) = port, !ranges.contains(chosen) { ranges.append(chosen) }
        return ranges
    }

    private func isOn(_ pattern: AlertPattern) -> Bool {
        let servers: Bool = switch pattern.servers {
        case .any: server == .any
        case .network(let network): server == .network(network)
        case nil: true
        }
        return servers && pattern.ports.map { port == .range($0) } ?? true
    }

    private func start(on pattern: AlertPattern) {
        switch pattern.servers {
        case .any: server = .any
        case .network(let network): server = .network(network)
        case nil: break
        }
        if let range = pattern.ports { port = .range(range) }
    }

    /// Back to this one server on this one port.
    private func narrow(from pattern: AlertPattern) {
        if pattern.servers != nil { server = .host }
        port = .thisPort
    }

    /// What the answer as chosen takes in beyond this alert.
    private var reach: AlertReach {
        alert.reach(of: decision(preferredAction), state: model.state, waiting: model.alerts)
    }

    private func headline(for pattern: AlertPattern) -> String {
        let app = alert.process.name
        let ports = pattern.ports.map { "ports \(Self.span($0))" } ?? Formatting.port(alert.port, proto: alert.proto)
        switch pattern.servers {
        case .any: return "\(app) keeps reaching new servers on \(ports)"
        case .network(let network): return "\(app) keeps reaching servers at \(network.familiarDescription) on \(ports)"
        case nil: return "\(app) reaches this server on one port after another"
        }
    }

    private func detail(of reach: AlertReach, on pattern: AlertPattern) -> String {
        guard isOn(pattern) else { return "Answered one at a time, each new one asks again." }
        guard let summary = summary(of: reach) else { return "One answer covers the ones still to come." }
        return "One answer covers the ones still to come. \(preferredAction == .allow ? "Allowing" : "Denying") also \(summary)."
    }

    /// "answers 40 more waiting alerts and replaces 526 earlier rules", or nil when there's nothing to say.
    private func summary(of reach: AlertReach) -> String? {
        var parts: [String] = []
        if !reach.alerts.isEmpty { parts.append("answers \(reach.alerts.count) more waiting alert\(reach.alerts.count == 1 ? "" : "s")") }
        if reach.rules > 0 { parts.append("replaces \(reach.rules.formatted()) earlier rule\(reach.rules == 1 ? "" : "s")") }
        return parts.isEmpty ? nil : parts.joined(separator: " and ")
    }

    static func span(_ range: PortRange) -> String { "\(range.lower)–\(range.upper)" }

    /// What happens if nobody answers in time.
    private var timeoutAction: RuleAction {
        let settings = model.state.settings
        if settings.alertTimeoutFollowsAdvice, let advice = alert.advice, advice.isConfident, let suggestion = advice.suggestion {
            return suggestion
        }
        return settings.alertTimeoutAction
    }

    // MARK: Answering

    private func decision(_ action: RuleAction) -> AlertDecision {
        var decision = AlertDecision(action: action, processScope: process, duration: duration, allUsers: !onlyMe, activeProfileOnly: onlyThisProfile)
        switch server {
        case .host: decision.remoteScope = alert.hostname == nil ? .address : .host
        case .domain: decision.remoteScope = .domain(domainOption ?? alert.hostname ?? "")
        case .network(let network):
            decision.remoteScope = .address
            decision.networkPrefix = network.prefixLength
        case .any: decision.remoteScope = .any
        }
        switch port {
        case .thisPort: break
        case .range(let range): decision.portRange = range
        case .anyPort: decision.portScope = .anyPort
        }
        return decision
    }

    private func answer(_ action: RuleAction) {
        let decision = decision(action)
        let reach = alert.reach(of: decision, state: model.state, waiting: model.alerts)
        // The rule answers the alerts it covers by itself; "the same way" is for the rest.
        let others = answerOthers ? otherAlertsFromApp.filter { !reach.alerts.contains($0.id) } : []
        Task { await model.resolve(alert, with: decision, alsoAnswering: others, offeringUndo: reach.rules > 0) }
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

/// Why an alert starts on more than its one server and port, and what one answer then takes in.
private struct PatternNote: View {
    let headline: String
    let detail: String
    /// Whether the choices below are on the pattern now.
    let isApplied: Bool
    let toggle: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "point.3.filled.connected.trianglepath.dotted")
                .font(.title3)
                .foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 2) {
                Text(headline).font(.callout.weight(.semibold))
                Text(detail).font(.caption).foregroundStyle(.secondary)
            }
            .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 6)
            Button(isApplied ? "Just This One" : "Cover Them All", action: toggle)
                .controlSize(.small)
                .help(isApplied ? "Answer for this one server and port only" : "Answer for all of them at once")
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.accentColor.opacity(0.12), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .accessibilityElement(children: .contain)
    }
}

/// For an app that's been allowed again and again: one answer for all of it.
private struct AllowEverywhereOffer: View {
    let appName: String
    let allowed: Int
    let allow: () -> Void

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "checkmark.circle.fill")
                .foregroundStyle(Color.allowed)
            Text("You've allowed \(appName) \(allowed) times and never denied it.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 6)
            Button("Allow Everywhere", action: allow)
                .controlSize(.small)
                .help("Lets \(appName) connect to any server on any port, without asking again")
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.allowed.opacity(0.1), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
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
