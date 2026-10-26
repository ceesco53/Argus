import ArgusKit
import SwiftUI
import UniformTypeIdentifiers

struct RulesView: View {
    @Environment(AppModel.self) private var model
    @State private var selection = Set<Rule.ID>()
    @State private var filter: Filter = .all
    @State private var profileFilter: UUID?? = .none
    @State private var editing: Rule?
    @State private var isNew = false
    @State private var sortOrder = [KeyPathComparator(\RuleRow.processName)]
    @AppStorage("rulesGroupedByProgram") private var groupByProgram = false

    enum Filter: String, CaseIterable, Identifiable {
        case all = "All Rules", allow = "Allow", deny = "Deny", temporary = "Temporary", groups = "From Rule Groups", disabled = "Disabled"
        case problems = "Problems"
        var id: String { rawValue }
    }

    /// Duplicates and rules that can never apply.
    private var issues: [UUID: RuleIssue] { RuleAnalysis.issues(in: model.state.rules) }

    var body: some View {
        @Bindable var model = model
        let issues = self.issues
        VStack(spacing: 0) {
            if model.engine == .monitor {
                MonitorModeBanner(compact: true).padding([.horizontal, .top], 16).padding(.bottom, 8)
            }
            if groupByProgram {
                groupedList(issues: issues)
            } else {
                table(issues: issues)
            }
        }
        .navigationTitle("Rules")
        .navigationSubtitle("\(model.state.rules.count) rules")
        .searchable(text: $model.ruleSearch, placement: .toolbar, prompt: "Programs, servers, notes")
        .toolbar { toolbar(issues: issues) }
        .sheet(item: $editing) { rule in
            RuleEditor(rule: rule, isNew: isNew)
        }
    }

    private func issueIcon(_ issue: RuleIssue?) -> some View {
        Group {
            if let issue {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .help(issue.explanation)
                    .accessibilityLabel(issue.explanation)
            }
        }
    }

    private func table(issues: [UUID: RuleIssue]) -> some View {
            Table(rows.sorted(using: sortOrder), selection: $selection, sortOrder: $sortOrder) {
                TableColumn("") { row in
                    issueIcon(issues[row.id])
                }
                .width(16)
                TableColumn("On") { row in
                    Toggle("Enabled", isOn: Binding(
                        get: { row.rule.isEnabled },
                        set: { value in Task { await model.setRules([row.id], enabled: value) } }))
                        .labelsHidden()
                        .disabled(row.rule.isFromRuleGroup)
                }
                .width(30)
                TableColumn("Action", value: \.actionName) { row in
                    HStack(spacing: 4) {
                        Image(systemName: row.rule.action == .allow ? "checkmark.circle.fill" : "xmark.octagon.fill")
                            .foregroundStyle(row.rule.action == .allow ? Color.allowed : Color.denied)
                        Text(row.rule.action.displayName)
                        if row.rule.isPriority {
                            Image(systemName: "exclamationmark.2").foregroundStyle(.orange).help("High priority")
                        }
                    }
                }
                .width(min: 70, ideal: 85)
                TableColumn("Program", value: \.processName) { row in
                    HStack(spacing: 6) {
                        if let path = row.rule.process.path {
                            AppIconView(identity: model.identity(for: path), size: 16)
                        } else {
                            Image(systemName: "square.grid.2x2").foregroundStyle(.secondary)
                        }
                        Text(row.processName).lineLimit(1)
                        if row.rule.codeRequirement != nil {
                            Image(systemName: "checkmark.seal").foregroundStyle(.tertiary).imageScale(.small)
                                .help("Only while the program keeps its code signature")
                        }
                    }
                }
                .width(min: 120, ideal: 170)
                TableColumn("Server", value: \.serverName) { row in
                    Text(row.serverName).lineLimit(1).truncationMode(.middle)
                        .foregroundStyle(row.rule.remote == .any ? .secondary : .primary)
                }
                .width(min: 130, ideal: 220)
                TableColumn("Port", value: \.portName) { row in
                    Text(row.portName).foregroundStyle(row.rule.ports == .any ? .secondary : .primary)
                }
                .width(min: 60, ideal: 90)
                TableColumn("Direction") { row in
                    Image(systemName: row.rule.direction == .incoming ? "arrow.down.left" : row.rule.direction == .both ? "arrow.left.arrow.right" : "arrow.up.right")
                        .foregroundStyle(.secondary)
                        .help(row.rule.direction.displayName)
                }
                .width(40)
                TableColumn("Profile", value: \.profileName) { row in
                    Text(row.profileName).foregroundStyle(row.rule.profileID == nil ? .secondary : .primary)
                }
                .width(min: 70, ideal: 100)
                TableColumn("Expires") { row in
                    if row.rule.expiration.isTemporary {
                        Label(row.rule.expiration.displayString, systemImage: "timer").foregroundStyle(.orange).lineLimit(1)
                    }
                }
                .width(min: 60, ideal: 130)
                TableColumn("Origin", value: \.originName) { row in
                    Text(row.originName).foregroundStyle(.secondary).lineLimit(1)
                }
                .width(min: 80, ideal: 130)
            }
            .contextMenu(forSelectionType: Rule.ID.self) { ids in
                menu(for: ids)
            } primaryAction: { ids in
                if let id = ids.first, let rule = model.rule(id: id), !rule.isFromRuleGroup { edit(rule) }
            }
            .overlay {
                if rows.isEmpty {
                    ContentUnavailableView("No rules", systemImage: "list.bullet.rectangle",
                                           description: Text("Rules appear when you answer alerts or use the monitor's allow and deny buttons."))
                }
            }
    }

    /// Each program's rules in its own section, any-program rules first.
    private func groupedList(issues: [UUID: RuleIssue]) -> some View {
        let groups = Dictionary(grouping: rows, by: \.processName)
            .sorted { a, b in
                let anyA = a.value.first?.rule.process == .any, anyB = b.value.first?.rule.process == .any
                return anyA != anyB ? anyA : a.key.localizedCaseInsensitiveCompare(b.key) == .orderedAscending
            }
        return List(selection: $selection) {
            ForEach(groups, id: \.key) { name, rows in
                Section {
                    ForEach(rows) { row in
                        HStack(spacing: 10) {
                            Toggle("Enabled", isOn: Binding(
                                get: { row.rule.isEnabled },
                                set: { value in Task { await model.setRules([row.id], enabled: value) } }))
                                .labelsHidden()
                                .disabled(row.rule.isFromRuleGroup)
                            Image(systemName: row.rule.action == .allow ? "checkmark.circle.fill" : "xmark.octagon.fill")
                                .foregroundStyle(row.rule.action == .allow ? Color.allowed : Color.denied)
                                .accessibilityLabel(row.rule.action.displayName)
                            Text(row.serverName).lineLimit(1).truncationMode(.middle)
                            Text(row.portName).foregroundStyle(.secondary)
                            Spacer()
                            if row.rule.expiration.isTemporary {
                                Label(row.rule.expiration.displayString, systemImage: "timer").font(.caption).foregroundStyle(.orange)
                            }
                            Text(row.profileName).font(.caption).foregroundStyle(.secondary)
                            issueIcon(issues[row.id])
                        }
                        .tag(row.id)
                    }
                } header: {
                    HStack(spacing: 6) {
                        if let path = rows.first?.rule.process.path {
                            AppIconView(identity: model.identity(for: path), size: 16)
                        } else {
                            Image(systemName: "square.grid.2x2")
                        }
                        Text(name)
                        Text("\(rows.count)").foregroundStyle(.secondary)
                    }
                }
            }
        }
        .listStyle(.inset)
        .contextMenu(forSelectionType: Rule.ID.self) { ids in
            menu(for: ids)
        } primaryAction: { ids in
            if let id = ids.first, let rule = model.rule(id: id), !rule.isFromRuleGroup { edit(rule) }
        }
    }

    @ToolbarContentBuilder
    private func toolbar(issues: [UUID: RuleIssue]) -> some ToolbarContent {
            let duplicates = issues.compactMap { id, issue -> UUID? in if case .duplicate = issue { id } else { nil } }
            ToolbarItemGroup {
                if !duplicates.isEmpty {
                    Button("Remove \(duplicates.count) Duplicate\(duplicates.count == 1 ? "" : "s")") {
                        Task { await model.deleteRules(duplicates) }
                    }
                    .help("Rules that do exactly what an older rule already does")
                }
                Toggle(isOn: $groupByProgram) {
                    Label("Group by Program", systemImage: "rectangle.grid.1x2")
                }
                .help("Group rules by the program they apply to")
                Button {
                    model.showChanges = true
                } label: {
                    Label("History", systemImage: "clock.arrow.circlepath")
                }
                .help("Recent changes, with undo")
                Picker("Show", selection: $filter) {
                    ForEach(Filter.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.menu)
                Picker("Profile", selection: $profileFilter) {
                    Text("All Profiles").tag(UUID??.none)
                    Text("Rules for Every Profile").tag(UUID??.some(nil))
                    ForEach(model.state.profiles) { Text($0.name).tag(UUID??.some($0.id)) }
                }
                .pickerStyle(.menu)
                Button {
                    edit(Rule(action: .deny), new: true)
                } label: {
                    Label("New Rule", systemImage: "plus")
                }
                .keyboardShortcut("n")
                Button {
                    Task { await model.deleteRules(selection) }
                } label: {
                    Label("Delete", systemImage: "trash")
                }
                .disabled(selection.isEmpty)
                .keyboardShortcut(.delete)
                Menu {
                    Button("Export Selected as Rule Group…") { export(rows.filter { selection.contains($0.id) }.map(\.rule)) }
                        .disabled(selection.isEmpty)
                    Button("Export All as Rule Group…") { export(model.state.rules) }
                } label: {
                    Label("Export", systemImage: "square.and.arrow.up")
                }
            }
    }

    // MARK: Rows

    private var rows: [RuleRow] {
        let term = model.ruleSearch.lowercased()
        let issues = filter == .problems ? self.issues : [:]
        let groupRules = model.state.ruleGroups.filter(\.isEnabled).flatMap(\.rules)
        let all = (filter == .groups ? groupRules : model.state.rules + (filter == .all ? groupRules : []))
        return all.filter { rule in
            switch filter {
            case .all, .groups: true
            case .allow: rule.action == .allow
            case .deny: rule.action == .deny
            case .temporary: rule.expiration.isTemporary
            case .disabled: !rule.isEnabled
            case .problems: issues[rule.id] != nil
            }
        }.filter { rule in
            switch profileFilter {
            case .none: true
            case .some(let id): rule.profileID == id
            }
        }.map { RuleRow(rule: $0, model: model) }.filter { row in
            term.isEmpty || row.processName.lowercased().contains(term) || row.serverName.lowercased().contains(term)
                || row.rule.notes.lowercased().contains(term) || (row.rule.process.path?.lowercased().contains(term) ?? false)
        }
    }

    @ViewBuilder
    private func menu(for ids: Set<Rule.ID>) -> some View {
        let rules = ids.compactMap { model.rule(id: $0) }.filter { !$0.isFromRuleGroup }
        if rules.count == 1, let rule = rules.first {
            Button("Edit…") { edit(rule) }
            Button("Duplicate") {
                var copy = rule
                copy.id = UUID()
                copy.origin = .user
                edit(copy, new: true)
            }
            Button(rule.isPriority ? "Make Normal Priority" : "Make High Priority") {
                var updated = rule
                updated.isPriority.toggle()
                Task { _ = await model.save(updated) }
            }
            Divider()
        }
        if !rules.isEmpty {
            Button("Enable") { Task { await model.setRules(rules.map(\.id), enabled: true) } }
            Button("Disable") { Task { await model.setRules(rules.map(\.id), enabled: false) } }
            Divider()
            Button("Delete", role: .destructive) { Task { await model.deleteRules(rules.map(\.id)) } }
        } else {
            Text("Rules from rule groups are managed by their subscription")
        }
    }

    private func edit(_ rule: Rule, new: Bool = false) {
        isNew = new
        editing = rule
    }

    private func export(_ rules: [Rule]) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "Argus Rules.lsrules"
        panel.allowedContentTypes = [UTType(filenameExtension: "lsrules") ?? .json]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        model.exportRules(rules, name: url.deletingPathExtension().lastPathComponent, to: url)
    }
}

/// Sortable presentation of a rule.
struct RuleRow: Identifiable {
    let rule: Rule
    let processName: String
    let serverName: String
    let portName: String
    let profileName: String
    let originName: String
    let actionName: String

    var id: UUID { rule.id }

    @MainActor
    init(rule: Rule, model: AppModel) {
        self.rule = rule
        processName = rule.process.path.map { model.processes[$0]?.identity.name ?? ProcessIdentity.defaultName(for: $0) } ?? "Any Program"
        serverName = rule.remote.displayString
        portName = rule.proto == .any ? rule.ports.displayString : "\(rule.ports == .any ? "Any" : rule.ports.displayString) \(rule.proto.displayName)"
        profileName = model.state.profile(id: rule.profileID)?.name ?? "All"
        if case .ruleGroup(let id) = rule.origin {
            originName = model.state.ruleGroup(id: id)?.name ?? "Rule group"
        } else {
            originName = rule.origin.displayName
        }
        actionName = rule.action.rawValue
    }
}
