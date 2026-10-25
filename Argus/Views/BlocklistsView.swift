import ArgusKit
import SwiftUI
import UniformTypeIdentifiers

struct BlocklistsView: View {
    @Environment(AppModel.self) private var model
    @State private var showSubscribe = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                intro
                if model.engine == .monitor { MonitorModeBanner(compact: true) }
                yourLists
                ForEach(CatalogEntry.Category.allCases, id: \.self) { category in
                    catalogSection(category)
                }
            }
            .padding(24)
        }
        .navigationTitle("Blocklists")
        .toolbar {
            ToolbarItemGroup {
                Button {
                    Task { await model.refreshGroups(nil) }
                } label: {
                    Label("Update All", systemImage: "arrow.clockwise")
                }
                .disabled(model.state.ruleGroups.allSatisfy { $0.url == nil })
                Button {
                    importFile()
                } label: {
                    Label("Import File", systemImage: "square.and.arrow.down")
                }
                Button {
                    showSubscribe = true
                } label: {
                    Label("Subscribe to URL", systemImage: "plus")
                }
            }
        }
        .sheet(isPresented: $showSubscribe) { SubscribeSheet() }
    }

    private var intro: some View {
        HStack(alignment: .top, spacing: 16) {
            Image(systemName: "shield.lefthalf.filled.badge.checkmark")
                .font(.system(size: 36))
                .foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 4) {
                Text("Community blocklists").font(.title2.weight(.semibold))
                Text("Lists of ad, tracking and malware servers, maintained by volunteers and refreshed automatically. Any app's connection to a listed server is denied, unless you've made a rule that allows that app.")
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var yourLists: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Your lists").font(.headline)
            if model.state.ruleGroups.isEmpty {
                Text("You haven't added any yet. HaGeZi Multi Light and FireHOL Level 1 are good, safe places to start.")
                    .foregroundStyle(.secondary)
                    .card()
            } else {
                VStack(spacing: 0) {
                    ForEach(model.state.ruleGroups) { group in
                        GroupRow(group: group)
                        if group.id != model.state.ruleGroups.last?.id { Divider().padding(.leading, 52) }
                    }
                }
                .card(padding: 4)
            }
        }
    }

    private func catalogSection(_ category: CatalogEntry.Category) -> some View {
        let entries = BlocklistCatalog.entries.filter { $0.category == category }
        return VStack(alignment: .leading, spacing: 10) {
            Text(category.rawValue).font(.headline)
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 280), spacing: 14)], spacing: 14) {
                ForEach(entries) { CatalogCard(entry: $0) }
            }
        }
    }

    private func importFile() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.plainText, .json, UTType(filenameExtension: "lsrules") ?? .json, .data]
        panel.message = "Choose a hosts file, a domain list, an IP list or a .lsrules rule group."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        Task { await model.importGroup(from: url) }
    }
}

private struct GroupRow: View {
    @Environment(AppModel.self) private var model
    let group: RuleGroup

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: group.url == nil ? "doc.text" : "antenna.radiowaves.left.and.right")
                .font(.title3)
                .foregroundStyle(group.isEnabled ? Color.accentColor : .secondary)
                .frame(width: 30)
            VStack(alignment: .leading, spacing: 2) {
                Text(group.name).fontWeight(.medium)
                HStack(spacing: 6) {
                    Text(group.entryCount > 0 ? "\(group.entryCount.formatted()) entries" : "Not downloaded yet")
                    if !group.rules.isEmpty { Text("· \(group.rules.count) rules") }
                    if let updated = group.lastUpdated { Text("· updated \(updated.relative)") }
                }
                .font(.caption)
                .foregroundStyle(.secondary)
                if let error = group.lastError {
                    Label(error, systemImage: "exclamationmark.triangle.fill").font(.caption).foregroundStyle(.orange)
                }
            }
            Spacer()
            if model.refreshingGroups.contains(group.id) {
                ProgressView().controlSize(.small)
            }
            Menu {
                if group.url != nil {
                    Button("Update Now") { Task { await model.refreshGroups([group.id]) } }
                }
                if let url = group.url {
                    Button("Copy URL") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(url.absoluteString, forType: .string)
                    }
                }
                if !group.rules.isEmpty {
                    Button("Show Rules") {
                        model.ruleSearch = ""
                        model.section = .rules
                    }
                }
                Divider()
                Button("Remove", role: .destructive) { Task { await model.deleteGroup(group.id) } }
            } label: {
                Image(systemName: "ellipsis.circle")
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
            Toggle("Enabled", isOn: Binding(get: { group.isEnabled }, set: { value in
                var updated = group
                updated.isEnabled = value
                Task { await model.save(updated) }
            }))
            .toggleStyle(.switch)
            .labelsHidden()
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 10)
    }
}

private struct CatalogCard: View {
    @Environment(AppModel.self) private var model
    let entry: CatalogEntry

    var body: some View {
        let subscribed = model.state.ruleGroups.first { $0.catalogID == entry.id || $0.url == entry.url }
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 1) {
                    Text(entry.name).font(.headline)
                    Text("by \(entry.maintainer)").font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                if entry.isRecommended { Pill(text: "Recommended", symbol: "star.fill", tint: .allowed) }
            }
            Text(entry.summary)
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxHeight: .infinity, alignment: .top)
            HStack {
                Text("~\(entry.approximateEntries.formatted(.number.notation(.compactName))) entries")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
                Link("Website", destination: entry.homepage).font(.caption)
                Spacer()
                if let subscribed {
                    if model.refreshingGroups.contains(subscribed.id) {
                        ProgressView().controlSize(.small)
                    } else {
                        Label("Added", systemImage: "checkmark.circle.fill").foregroundStyle(Color.allowed).font(.callout)
                    }
                } else {
                    Button("Add") { Task { await model.subscribe(to: entry) } }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.small)
                }
            }
        }
        .frame(minHeight: 130)
        .card()
    }
}

private struct SubscribeSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var urlText = ""
    @State private var name = ""
    @State private var format: BlocklistFormat = .automatic

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Subscribe to a Rule Group").font(.title2.weight(.semibold))
            Text("Argus downloads the list now and checks it for updates every day. It understands Little Snitch rule groups (.lsrules), hosts files, domain lists and IP address lists.")
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Form {
                TextField("URL", text: $urlText, prompt: Text("https://example.com/blocklist.txt"))
                TextField("Name", text: $name, prompt: Text("Optional"))
                Picker("Format", selection: $format) {
                    ForEach(BlocklistFormat.allCases, id: \.self) { Text($0.displayName).tag($0) }
                }
            }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Subscribe") {
                    guard let url = URL(string: urlText.trimmingCharacters(in: .whitespaces)) else { return }
                    Task { await model.subscribe(url: url, name: name.isEmpty ? url.lastPathComponent : name, format: format) }
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(URL(string: urlText)?.scheme?.hasPrefix("http") != true)
            }
        }
        .padding(24)
        .frame(width: 500)
    }
}
