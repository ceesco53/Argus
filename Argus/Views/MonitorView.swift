import ArgusKit
import SwiftUI

struct MonitorView: View {
    @Environment(AppModel.self) private var model
    @State private var search = ""
    @State private var filter: Filter = .all
    @State private var order: Order = .recent
    @State private var selectedConnection: ConnectionRecord.ID?
    @State private var showInspector = false
    @State private var editingRule: Rule?
    @State private var grouping: Grouping = .apps
    @State private var selectedDomain: String?

    enum Filter: String, CaseIterable, Identifiable {
        case all = "All", active = "Active Now", blocked = "Blocked", unapproved = "No Rule Yet", new = "New This Week"
        var id: String { rawValue }
    }

    enum Grouping: String, CaseIterable, Identifiable {
        case apps = "Apps", domains = "Domains"
        var id: String { rawValue }
    }

    struct DomainRow: Identifiable {
        let domain: String
        var bytes: UInt64 = 0
        var connections = 0
        var blocked = 0
        var apps = Set<String>()
        var lastSeen = Date.distantPast
        var id: String { domain }
    }

    private static func domain(of connection: ConnectionRecord) -> String {
        connection.hostname.flatMap(DomainName.registrableDomain) ?? connection.remote
    }

    private var weekAgo: Date { Date().addingTimeInterval(-7 * 86_400) }

    enum Order: String, CaseIterable, Identifiable {
        case recent = "Most Recent", traffic = "Most Data", name = "Name"
        var id: String { rawValue }
    }

    var body: some View {
        @Bindable var model = model
        HSplitView {
            Group {
                if grouping == .apps { processList } else { domainList }
            }
            .frame(minWidth: 230, idealWidth: 270, maxWidth: 400)
            Group {
                if grouping == .apps { detail } else { domainDetail }
            }
            .frame(minWidth: 460, maxWidth: .infinity)
        }
        .navigationTitle("Network Monitor")
        .navigationSubtitle(model.isEnforcing ? "" : "Observing only")
        .searchable(text: $search, placement: .toolbar, prompt: "Apps, servers or addresses")
        .toolbar {
            ToolbarItem(placement: .principal) {
                Picker("Group by", selection: $grouping) {
                    ForEach(Grouping.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                .help("List apps, or the domains they talk to")
            }
            ToolbarItem {
                Picker("Show", selection: $filter) {
                    ForEach(Filter.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.menu)
                .help("Filter connections")
            }
            ToolbarItem {
                Button {
                    showInspector.toggle()
                } label: {
                    Image(systemName: "sidebar.trailing")
                }
                .help("Show connection details")
            }
        }
        .inspector(isPresented: $showInspector) {
            ConnectionInspector(connectionID: selectedConnection) { editingRule = $0 }
                .inspectorColumnWidth(min: 280, ideal: 320, max: 420)
        }
        .sheet(item: $editingRule) { rule in
            RuleEditor(rule: rule, isNew: true)
        }
    }

    // MARK: Process list

    private var visibleProcesses: [ProcessRecord] {
        let term = search.lowercased()
        let matching = model.processes.values.filter { process in
            switch filter {
            case .all: true
            case .active: process.activeFlows > 0 || model.processRates[process.id] != nil
            case .blocked: process.denyCount > 0
            case .unapproved: process.unapprovedCount > 0
            case .new: process.firstSeen > weekAgo
            }
        }.filter { process in
            term.isEmpty || process.identity.name.lowercased().contains(term) || process.id.lowercased().contains(term)
                || model.connections(of: process.id).contains { $0.remote.contains(term) || $0.addresses.contains { $0.contains(term) } }
        }
        return matching.sorted { a, b in
            switch order {
            case .recent: a.lastSeen > b.lastSeen
            case .traffic: a.totalBytes > b.totalBytes
            case .name: a.identity.name.localizedCaseInsensitiveCompare(b.identity.name) == .orderedAscending
            }
        }
    }

    private var processList: some View {
        @Bindable var model = model
        return VStack(spacing: 0) {
            List(selection: $model.selectedProcessPath) {
                AllAppsRow(count: model.processes.count)
                    .tag(nil as String?)
                ForEach(visibleProcesses) { process in
                    ProcessRow(process: process, rate: model.processRates[process.id])
                        .tag(process.id as String?)
                        .contextMenu { processMenu(process) }
                }
            }
            .listStyle(.inset)
            .overlay {
                if model.processes.isEmpty {
                    ContentUnavailableView("Waiting for traffic", systemImage: "eye",
                                           description: Text("Programs appear here as soon as they use the network."))
                }
            }
            Divider()
            HStack {
                Picker("Sort", selection: $order) {
                    ForEach(Order.allCases) { Text($0.rawValue).tag($0) }
                }
                .labelsHidden()
                .fixedSize()
                Spacer()
                Text("\(visibleProcesses.count) apps").font(.caption).foregroundStyle(.secondary)
            }
            .controlSize(.small)
            .padding(8)
        }
    }

    @ViewBuilder
    private func processMenu(_ process: ProcessRecord) -> some View {
        Button("Deny All Connections") {
            Task { _ = await model.save(Rule(action: .deny, process: .path(process.id), codeRequirement: process.identity.designatedRequirement)) }
        }
        Button("Allow All Connections") {
            Task { _ = await model.save(Rule(action: .allow, process: .path(process.id), codeRequirement: process.identity.designatedRequirement)) }
        }
        Divider()
        Button("Show Rules") {
            model.ruleSearch = process.identity.name
            model.section = .rules
        }
        Button("Show in Finder") {
            NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: process.identity.appBundlePath ?? process.id)])
        }
    }

    // MARK: Detail

    private func passesFilter(_ connection: ConnectionRecord) -> Bool {
        switch filter {
        case .all: true
        case .active: connection.activeFlows > 0
        case .blocked: connection.isBlocked
        case .unapproved: connection.lastVerdict.reason.isUnapproved
        case .new: connection.firstSeen > weekAgo
        }
    }

    private var visibleConnections: [ConnectionRecord] {
        let term = search.lowercased()
        let base = model.selectedProcessPath.map { model.connections(of: $0) } ?? Array(model.connections.values)
        return base.filter(passesFilter).filter { connection in
            term.isEmpty || connection.remote.contains(term) || connection.addresses.contains { $0.contains(term) }
                || model.selectedProcessPath != nil || model.identity(for: connection.processPath).name.lowercased().contains(term)
        }
    }

    @ViewBuilder
    private var detail: some View {
        VStack(spacing: 0) {
            if let path = model.selectedProcessPath, let process = model.processes[path] {
                ProcessHeader(process: process)
                    .padding(16)
                Divider()
            } else {
                AllAppsHeader()
                    .padding(16)
                Divider()
            }
            ConnectionTable(
                connections: visibleConnections,
                showProgram: model.selectedProcessPath == nil,
                selection: $selectedConnection,
                onOpen: { showInspector = true },
                onCreateRule: { editingRule = $0 })
        }
    }

    // MARK: Domains

    private var domainRows: [DomainRow] {
        let term = search.lowercased()
        var rows: [String: DomainRow] = [:]
        for connection in model.connections.values where passesFilter(connection) {
            let domain = Self.domain(of: connection)
            var row = rows[domain] ?? DomainRow(domain: domain)
            row.bytes += connection.totalBytes
            row.connections += connection.connectCount
            row.blocked += connection.denyCount
            row.apps.insert(connection.processPath)
            row.lastSeen = max(row.lastSeen, connection.lastSeen)
            rows[domain] = row
        }
        return rows.values.filter { term.isEmpty || $0.domain.contains(term) }.sorted { a, b in
            switch order {
            case .recent: a.lastSeen > b.lastSeen
            case .traffic: a.bytes > b.bytes
            case .name: a.domain < b.domain
            }
        }
    }

    private var domainList: some View {
        let rows = domainRows
        return VStack(spacing: 0) {
            List(selection: $selectedDomain) {
                ForEach(rows) { row in
                    HStack(spacing: 10) {
                        Image(systemName: "globe")
                            .font(.title3)
                            .foregroundStyle(row.blocked > 0 && row.blocked == row.connections ? Color.denied : .secondary)
                            .frame(width: 28)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(row.domain).fontWeight(.medium).lineLimit(1)
                            Text("\(row.apps.count) app\(row.apps.count == 1 ? "" : "s") · \(row.connections.formatted()) connections")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer(minLength: 4)
                        VStack(alignment: .trailing, spacing: 2) {
                            Text(Formatting.bytes(row.bytes)).font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                            if row.blocked > 0 {
                                Text("\(row.blocked.formatted()) blocked").font(.caption2).foregroundStyle(Color.denied)
                            }
                        }
                    }
                    .padding(.vertical, 3)
                    .tag(row.domain)
                    .accessibilityElement(children: .combine)
                }
            }
            .listStyle(.inset)
            Divider()
            HStack {
                Picker("Sort", selection: $order) {
                    ForEach(Order.allCases) { Text($0.rawValue).tag($0) }
                }
                .labelsHidden()
                .fixedSize()
                Spacer()
                Text("\(rows.count) domains").font(.caption).foregroundStyle(.secondary)
            }
            .controlSize(.small)
            .padding(8)
        }
    }

    @ViewBuilder
    private var domainDetail: some View {
        if let domain = selectedDomain {
            let connections = model.connections.values.filter { Self.domain(of: $0) == domain && passesFilter($0) }
            let apps = Set(connections.map(\.processPath)).map { model.identity(for: $0) }.sorted { $0.name < $1.name }
            VStack(spacing: 0) {
                VStack(alignment: .leading, spacing: 8) {
                    Text(domain).font(.title2.weight(.semibold))
                    HStack(spacing: 6) {
                        ForEach(apps.prefix(12), id: \.path) { identity in
                            AppIconView(identity: identity, size: 20).help(identity.name)
                        }
                        Text(apps.map(\.name).joined(separator: ", ")).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                    }
                    HStack {
                        Menu("Rule for Every App") {
                            Button("Allow \(domain) for Every App") {
                                Task { _ = await model.save(Rule(action: .allow, remote: .domain(domain), notes: "From the domain view")) }
                            }
                            Button("Block \(domain) for Every App") {
                                Task { _ = await model.save(Rule(action: .deny, remote: .domain(domain), notes: "From the domain view")) }
                            }
                        }
                        .fixedSize()
                        if let url = researchURL(for: domain) { Link("Research \(domain)", destination: url).font(.callout) }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(16)
                Divider()
                ConnectionTable(
                    connections: connections,
                    showProgram: true,
                    selection: $selectedConnection,
                    onOpen: { showInspector = true },
                    onCreateRule: { editingRule = $0 })
            }
        } else {
            ContentUnavailableView("Choose a domain", systemImage: "globe",
                                   description: Text("See which apps talk to it, how much, and what was blocked."))
        }
    }
}

private struct AllAppsRow: View {
    let count: Int

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "square.grid.2x2.fill")
                .font(.title3)
                .foregroundStyle(.tint)
                .frame(width: 28, height: 28)
            VStack(alignment: .leading, spacing: 1) {
                Text("All Apps").fontWeight(.medium)
                Text("\(count) programs").font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 3)
    }
}

private struct ProcessRow: View {
    let process: ProcessRecord
    let rate: Rate?

    var body: some View {
        HStack(spacing: 10) {
            AppIconView(identity: process.identity, size: 28)
                .overlay(alignment: .bottomTrailing) {
                    if process.activeFlows > 0 {
                        Circle().fill(Color.allowed).frame(width: 8, height: 8)
                            .overlay(Circle().stroke(.background, lineWidth: 1.5))
                    }
                }
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 4) {
                    Text(process.identity.name).fontWeight(.medium).lineLimit(1)
                    if process.identity.signature.isWarning {
                        Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange).imageScale(.small)
                            .help(process.identity.signature.displayName)
                    }
                }
                Text(process.subtitle).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer(minLength: 4)
            VStack(alignment: .trailing, spacing: 2) {
                if let rate, rate.total > 0 {
                    RateLabel(rate: rate)
                } else {
                    Text(Formatting.bytes(process.totalBytes)).font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                }
                HStack(spacing: 4) {
                    if process.unapprovedCount > 0 {
                        Circle().fill(Color.unapproved).frame(width: 6, height: 6).help("Has connections without a rule")
                    }
                    if process.denyCount > 0 {
                        Circle().fill(Color.denied).frame(width: 6, height: 6).help("Has denied connections")
                    }
                }
            }
        }
        .padding(.vertical, 3)
    }
}

private struct AllAppsHeader: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        HStack(alignment: .center, spacing: 14) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Every connection").font(.title2.weight(.semibold))
                Text("\(model.connections.count.formatted()) destinations from \(model.processes.count) programs")
                    .foregroundStyle(.secondary)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 4) {
                RateLabel(rate: model.currentRate)
                Sparkline(values: model.recentTraffic.suffix(60).map { Double($0.total) })
                    .frame(width: 160, height: 28)
            }
        }
    }
}

private struct ProcessHeader: View {
    @Environment(AppModel.self) private var model
    let process: ProcessRecord
    @State private var history: [TrafficBucket] = []

    var body: some View {
        let identity = process.identity
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 14) {
                AppIconView(identity: identity, size: 52)
                VStack(alignment: .leading, spacing: 4) {
                    Text(identity.name).font(.title2.weight(.semibold))
                    Text(identity.path)
                        .font(.caption.monospaced())
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                    HStack(spacing: 12) {
                        SignatureBadge(kind: identity.signature)
                        if let team = identity.teamIdentifier {
                            Text("Team \(team)").font(.caption).foregroundStyle(.secondary)
                        }
                        if !process.viaPaths.isEmpty {
                            Text("via \(process.viaPaths.map { ProcessIdentity.defaultName(for: $0) }.joined(separator: ", "))")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        if process.userIDs.count > 1 || process.userIDs.first.map({ $0 != getuid() }) == true {
                            Text("Users: \(process.userIDs.map { SystemInfo.userName(for: $0) }.joined(separator: ", "))")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
                Spacer()
                VStack(alignment: .trailing, spacing: 6) {
                    let rules = model.rules(for: process.id)
                    Button("\(rules.count) Rule\(rules.count == 1 ? "" : "s")") {
                        model.ruleSearch = identity.name
                        model.section = .rules
                    }
                    Menu("Block App") {
                        Button("Deny All Connections") {
                            Task { _ = await model.save(Rule(action: .deny, process: .path(process.id), codeRequirement: identity.designatedRequirement)) }
                        }
                        Button("Deny Internet, Allow Local Network") {
                            Task {
                                _ = await model.save(Rule(action: .deny, process: .path(process.id), codeRequirement: identity.designatedRequirement))
                                _ = await model.save(Rule(action: .allow, process: .path(process.id), codeRequirement: identity.designatedRequirement, remote: .localNetwork))
                            }
                        }
                    }
                    .fixedSize()
                }
            }
            HStack(spacing: 24) {
                metric("Received", Formatting.bytes(process.bytesIn), .incoming)
                metric("Sent", Formatting.bytes(process.bytesOut), .outgoing)
                metric("Connections", process.connectCount.formatted(), .primary)
                metric("Denied", process.denyCount.formatted(), process.denyCount > 0 ? .denied : .primary)
                metric("First seen", process.firstSeen.formatted(date: .abbreviated, time: .shortened), .primary)
                Spacer()
            }
            TrafficChart(buckets: history, resolution: .minute, height: 70)
        }
        .task(id: process.id) {
            while !Task.isCancelled {
                if case .traffic(let buckets)? = await model.perform(.getTraffic(TrafficQuery(processPath: process.id, resolution: .minute, since: Date().addingTimeInterval(-3600)))) {
                    history = buckets
                }
                try? await Task.sleep(for: .seconds(15))
            }
        }
    }

    private func metric(_ title: String, _ value: String, _ color: Color) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(value).font(.headline.monospacedDigit()).foregroundStyle(color)
            Text(title).font(.caption).foregroundStyle(.secondary)
        }
    }
}

private struct ConnectionTable: View {
    @Environment(AppModel.self) private var model
    let connections: [ConnectionRecord]
    let showProgram: Bool
    @Binding var selection: ConnectionRecord.ID?
    let onOpen: () -> Void
    let onCreateRule: (Rule) -> Void
    @State private var sortOrder = [KeyPathComparator(\ConnectionRecord.lastSeen, order: .reverse)]

    var body: some View {
        Table(connections.sorted(using: sortOrder), selection: $selection, sortOrder: $sortOrder) {
            TableColumn("") { connection in
                VerdictBadge(verdict: connection.lastVerdict, compact: true)
            }
            .width(22)
            TableColumn("Program") { connection in
                let identity = model.identity(for: connection.processPath)
                HStack(spacing: 6) {
                    AppIconView(identity: identity, size: 16)
                    Text(identity.name).lineLimit(1)
                }
            }
            .width(min: 90, ideal: 120)
            .defaultVisibility(showProgram ? .visible : .hidden)
            TableColumn("Server", value: \.remote) { connection in
                HStack(spacing: 4) {
                    if connection.direction == .incoming {
                        Image(systemName: "arrow.down.left").foregroundStyle(.secondary).help("Incoming connection")
                    }
                    Text(connection.remote).lineLimit(1).truncationMode(.middle)
                    if connection.hostnameSource == .reverseLookup {
                        Text("≈").foregroundStyle(.tertiary).help("Name from reverse DNS; the app may have used a different name")
                    }
                }
            }
            .width(min: 140, ideal: 220)
            TableColumn("Location") { connection in
                CountryLabel(country: model.geo.country(for: connection))
            }
            .width(min: 60, ideal: 100)
            TableColumn("Port", value: \.port) { connection in
                Text(Formatting.service(port: connection.port, proto: connection.proto) ?? "\(connection.port)")
                    .help(Formatting.endpoint(port: connection.port, proto: connection.proto))
            }
            .width(min: 50, ideal: 70)
            TableColumn("Data", value: \.totalBytes) { connection in
                Text("↓\(Formatting.bytes(connection.bytesIn))  ↑\(Formatting.bytes(connection.bytesOut))")
                    .font(.callout.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
            .width(min: 110, ideal: 130)
            TableColumn("Last Seen", value: \.lastSeen) { connection in
                Text(connection.activeFlows > 0 ? "Open now" : connection.lastSeen.relative)
                    .foregroundStyle(connection.activeFlows > 0 ? Color.allowed : .secondary)
            }
            .width(min: 70, ideal: 90)
            TableColumn("Rule") { connection in
                QuickRuleButtons(model: model, connection: connection)
            }
            .width(64)
        }
        .contextMenu(forSelectionType: ConnectionRecord.ID.self) { ids in
            if let id = ids.first, let connection = model.connections[id] {
                connectionMenu(connection)
            }
        } primaryAction: { ids in
            selection = ids.first
            onOpen()
        }
        .overlay {
            if connections.isEmpty {
                ContentUnavailableView("No connections", systemImage: "point.3.connected.trianglepath.dotted",
                                       description: Text("Nothing matches the current filter."))
            }
        }
    }

    @ViewBuilder
    private func connectionMenu(_ connection: ConnectionRecord) -> some View {
        Button("Always Allow") { Task { await model.quickRule(.allow, for: connection) } }
        Button("Always Deny") { Task { await model.quickRule(.deny, for: connection) } }
        if let host = connection.hostname, let domain = DomainName.registrableDomain(of: host) {
            Divider()
            Button("Allow All of \(domain)") { Task { await model.quickRule(.allow, for: connection, wholeDomain: true) } }
            Button("Deny All of \(domain)") { Task { await model.quickRule(.deny, for: connection, wholeDomain: true) } }
            Button("Deny \(domain) for Every App") { Task { await model.quickRule(.deny, for: connection, wholeDomain: true, anyProcess: true) } }
        }
        Divider()
        Button("New Rule…") { onCreateRule(Rule.prefilled(from: connection, identity: model.identity(for: connection.processPath))) }
        if let host = connection.hostname, let url = researchURL(for: host) {
            Button("Research \(host)") { NSWorkspace.shared.open(url) }
        }
        Button("Copy Address") {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(connection.addresses.first ?? connection.remote, forType: .string)
        }
    }
}

/// Inline allow/deny switch for a monitor row; creates a rule for exactly this connection.
struct QuickRuleButtons: View {
    // Passed in rather than read from the environment: table cells on macOS don't reliably inherit it.
    let model: AppModel
    let connection: ConnectionRecord

    var body: some View {
        let ruled: RuleAction? = if case .rule = connection.lastVerdict.reason { connection.lastVerdict.action } else { nil }
        HStack(spacing: 2) {
            button(.allow, symbol: "checkmark", active: ruled == .allow)
            button(.deny, symbol: "xmark", active: ruled == .deny)
        }
    }

    private func button(_ action: RuleAction, symbol: String, active: Bool) -> some View {
        Button {
            Task { await model.quickRule(action, for: connection) }
        } label: {
            Image(systemName: symbol)
                .font(.caption.weight(.bold))
                .frame(width: 22, height: 18)
                .foregroundStyle(active ? .white : .secondary)
                .background(active ? (action == .allow ? Color.allowed : Color.denied) : Color.secondary.opacity(0.12),
                            in: RoundedRectangle(cornerRadius: 5, style: .continuous))
        }
        .buttonStyle(.plain)
        .help(action == .allow ? "Always allow this connection" : "Always deny this connection")
        .accessibilityLabel(action == .allow ? "Always allow \(connection.remote)" : "Always deny \(connection.remote)")
    }
}

extension Rule {
    /// A rule matching one monitor row, ready for the editor.
    static func prefilled(from connection: ConnectionRecord, identity: ProcessIdentity) -> Rule {
        let remote: RemoteMatch = if let host = connection.hostname, connection.hostnameSource != .reverseLookup {
            .host(host)
        } else {
            connection.addresses.first.map(RemoteMatch.address) ?? .any
        }
        return Rule(
            action: connection.isBlocked ? .allow : .deny,
            process: .path(connection.processPath),
            codeRequirement: identity.designatedRequirement,
            remote: remote,
            ports: .single(connection.port),
            proto: connection.proto == .tcp ? .tcp : connection.proto == .udp ? .udp : .any,
            direction: connection.direction == .incoming ? .incoming : .outgoing)
    }
}

struct ConnectionInspector: View {
    @Environment(AppModel.self) private var model
    let connectionID: ConnectionRecord.ID?
    let onCreateRule: (Rule) -> Void

    var body: some View {
        if let id = connectionID, let connection = model.connections[id] {
            let identity = model.identity(for: connection.processPath)
            Form {
                Section {
                    VStack(alignment: .leading, spacing: 6) {
                        Text(connection.remote).font(.title3.weight(.semibold)).textSelection(.enabled)
                        VerdictBadge(verdict: connection.lastVerdict)
                        Text(connection.lastVerdict.reason.explanation(in: model.state))
                            .font(.caption).foregroundStyle(.secondary)
                        if let rule = model.rule(id: connection.lastVerdict.reason.ruleID), !rule.isFromRuleGroup {
                            Button("Edit Rule…") { onCreateRule(rule) }.buttonStyle(.link)
                        }
                    }
                }
                Section("Program") {
                    LabeledContent("Name") {
                        HStack { AppIconView(identity: identity, size: 16); Text(identity.name) }
                    }
                    LabeledContent("Signature") { SignatureBadge(kind: identity.signature) }
                    LabeledContent("Path") { Text(identity.path).font(.caption.monospaced()).textSelection(.enabled) }
                }
                Section("Server") {
                    if let host = connection.hostname {
                        LabeledContent("Hostname", value: host)
                        if connection.hostnameSource == .reverseLookup {
                            Text("Named by reverse DNS. The app may have asked for a different name.").font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    LabeledContent("Addresses") {
                        VStack(alignment: .trailing) {
                            ForEach(connection.addresses, id: \.self) { Text($0).textSelection(.enabled) }
                        }
                    }
                    LabeledContent("Location") { CountryLabel(country: model.geo.country(for: connection)) }
                    LabeledContent("Port", value: Formatting.endpoint(port: connection.port, proto: connection.proto))
                    LabeledContent("Direction", value: connection.direction == .incoming ? "Incoming" : "Outgoing")
                }
                Section("Activity") {
                    LabeledContent("First seen", value: connection.firstSeen.formatted(date: .abbreviated, time: .standard))
                    LabeledContent("Last seen", value: connection.lastSeen.formatted(date: .abbreviated, time: .standard))
                    LabeledContent("Connections", value: "\(connection.connectCount) (\(connection.allowCount) allowed, \(connection.denyCount) denied)")
                    LabeledContent("Open now", value: "\(connection.activeFlows)")
                    LabeledContent("Received", value: Formatting.bytes(connection.bytesIn))
                    LabeledContent("Sent", value: Formatting.bytes(connection.bytesOut))
                }
                Section {
                    HStack {
                        Button("Always Allow") { Task { await model.quickRule(.allow, for: connection) } }
                        Button("Always Deny") { Task { await model.quickRule(.deny, for: connection) } }
                    }
                    Button("Custom Rule…") { onCreateRule(Rule.prefilled(from: connection, identity: identity)) }
                    if let host = connection.hostname, let url = researchURL(for: host) {
                        Link("Research this server", destination: url)
                    }
                }
            }
            .formStyle(.grouped)
        } else {
            ContentUnavailableView("No Selection", systemImage: "cursorarrow.click",
                                   description: Text("Double-click a connection to see everything Argus knows about it."))
        }
    }
}
