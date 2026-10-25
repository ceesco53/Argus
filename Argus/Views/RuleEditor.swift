import ArgusKit
import SwiftUI
import UniformTypeIdentifiers

/// Creates or edits a rule with every option Argus supports.
struct RuleEditor: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    @State private var rule: Rule
    let isNew: Bool

    @State private var remoteKind: RemoteKind
    @State private var remoteValue: String
    @State private var portText: String
    @State private var pinSignature: Bool
    @State private var validity: Validity
    @State private var untilDate: Date
    @State private var problem: String?

    enum RemoteKind: String, CaseIterable, Identifiable {
        case any = "Any Server", localNetwork = "Local Network", host = "Host", domain = "Domain", address = "IP Address or Network"
        var id: String { rawValue }
    }

    enum Validity: String, CaseIterable, Identifiable {
        case forever = "Forever", until = "Until a Date", keep = "Keep Current Expiry"
        var id: String { rawValue }
    }

    init(rule: Rule, isNew: Bool) {
        _rule = State(initialValue: rule)
        self.isNew = isNew
        let (kind, value): (RemoteKind, String) = switch rule.remote {
        case .any: (.any, "")
        case .localNetwork: (.localNetwork, "")
        case .host(let h): (.host, h)
        case .domain(let d): (.domain, d)
        case .address(let a): (.address, a)
        }
        _remoteKind = State(initialValue: kind)
        _remoteValue = State(initialValue: value)
        _portText = State(initialValue: rule.ports == .any ? "" : rule.ports.displayString)
        _pinSignature = State(initialValue: rule.codeRequirement != nil)
        switch rule.expiration {
        case .never:
            _validity = State(initialValue: .forever)
            _untilDate = State(initialValue: Date().addingTimeInterval(3600))
        case .date(let date):
            _validity = State(initialValue: .until)
            _untilDate = State(initialValue: date)
        default:
            _validity = State(initialValue: .keep)
            _untilDate = State(initialValue: Date().addingTimeInterval(3600))
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Section {
                    Picker("Action", selection: $rule.action) {
                        Label("Allow", systemImage: "checkmark.circle.fill").tag(RuleAction.allow)
                        Label("Deny", systemImage: "xmark.octagon.fill").tag(RuleAction.deny)
                    }
                    .pickerStyle(.segmented)
                }

                Section("Program") {
                    processPicker
                    if rule.process.path != nil {
                        Toggle("Only while it keeps its current code signature", isOn: $pinSignature)
                            .disabled(signatureRequirement == nil)
                            .help("Protects against malware replacing the program. Argus blocks it if its signature changes.")
                    }
                }

                Section("Server") {
                    Picker("Connecting to", selection: $remoteKind) {
                        ForEach(RemoteKind.allCases) { Text($0.rawValue).tag($0) }
                    }
                    switch remoteKind {
                    case .host:
                        TextField("Hostname", text: $remoteValue, prompt: Text("api.example.com"))
                    case .domain:
                        TextField("Domain", text: $remoteValue, prompt: Text("example.com — includes all subdomains"))
                    case .address:
                        TextField("Address", text: $remoteValue, prompt: Text("203.0.113.7 or 203.0.113.0/24"))
                    case .any, .localNetwork:
                        EmptyView()
                    }
                    TextField("Ports", text: $portText, prompt: Text("Any port — or 443, 80, 8000-8100"))
                    Picker("Protocol", selection: $rule.proto) {
                        ForEach(ProtocolMatch.allCases, id: \.self) { Text($0.displayName).tag($0) }
                    }
                    Picker("Direction", selection: $rule.direction) {
                        ForEach(DirectionMatch.allCases, id: \.self) { Text($0.displayName).tag($0) }
                    }
                }

                Section("Scope") {
                    Picker("Users", selection: $rule.userID) {
                        Text("All users of this Mac").tag(UInt32?.none)
                        Text("Only \(SystemInfo.userName(for: getuid()))").tag(UInt32?.some(getuid()))
                    }
                    Picker("Profile", selection: $rule.profileID) {
                        Text("Every profile").tag(UUID?.none)
                        ForEach(model.state.profiles) { profile in
                            Label(profile.name, systemImage: profile.symbolName).tag(UUID?.some(profile.id))
                        }
                    }
                    Picker("Valid", selection: $validity) {
                        Text("Forever").tag(Validity.forever)
                        Text("Until a date").tag(Validity.until)
                        if case .untilQuit = rule.expiration { Text(rule.expiration.displayString).tag(Validity.keep) }
                        if case .untilRestart = rule.expiration { Text(rule.expiration.displayString).tag(Validity.keep) }
                    }
                    if validity == .until {
                        DatePicker("Expires", selection: $untilDate, in: Date()...)
                    }
                    Toggle(isOn: $rule.isPriority) {
                        Text("High priority")
                        Text("Wins over more specific rules")
                    }
                    Toggle("Enabled", isOn: $rule.isEnabled)
                }

                Section("Notes") {
                    TextField("Notes", text: $rule.notes, prompt: Text("Why this rule exists"), axis: .vertical)
                        .lineLimit(2...4)
                        .labelsHidden()
                }
            }
            .formStyle(.grouped)

            Divider()
            HStack {
                if let problem {
                    Label(problem, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange).font(.callout)
                } else {
                    Text(preview.summary).font(.callout).foregroundStyle(.secondary).lineLimit(2)
                }
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button(isNew ? "Add Rule" : "Save") { save() }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
            }
            .padding(16)
        }
        .frame(width: 560, height: 680)
    }

    // MARK: Program picker

    private var processPicker: some View {
        HStack {
            if let path = rule.process.path {
                AppIconView(identity: model.identity(for: path), size: 24)
                VStack(alignment: .leading) {
                    Text(model.identity(for: path).name)
                    Text(path).font(.caption.monospaced()).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                }
            } else {
                Image(systemName: "square.grid.2x2").frame(width: 24)
                Text("Any program")
            }
            Spacer()
            Menu("Choose") {
                Button("Any Program") { rule.process = .any }
                Button("Choose an App…") { chooseApp() }
                Divider()
                ForEach(model.processes.values.sorted { $0.identity.name.localizedCaseInsensitiveCompare($1.identity.name) == .orderedAscending }.prefix(60)) { process in
                    Button(process.identity.name) { rule.process = .path(process.id) }
                }
            }
            .fixedSize()
        }
    }

    private func chooseApp() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.application, .unixExecutable, .executable]
        panel.directoryURL = URL(fileURLWithPath: "/Applications")
        panel.treatsFilePackagesAsDirectories = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        // Rules match executables; for an app bundle use its main executable.
        let path = Bundle(url: url)?.executableURL?.path ?? url.path
        rule.process = .path(path)
    }

    private var signatureRequirement: String? {
        guard let path = rule.process.path else { return nil }
        return model.identity(for: path).designatedRequirement ?? CodeSignature.identity(path: path).designatedRequirement
    }

    // MARK: Saving

    private var preview: Rule {
        var preview = rule
        preview.remote = remote ?? .any
        preview.ports = PortMatch.parse(portText) ?? .any
        return preview
    }

    private var remote: RemoteMatch? {
        let value = remoteValue.trimmingCharacters(in: .whitespaces).lowercased()
        switch remoteKind {
        case .any: return .any
        case .localNetwork: return .localNetwork
        case .host: return DomainSet.normalize(value).map(RemoteMatch.host) ?? (IPAddress(value) != nil ? .host(value) : nil)
        case .domain: return DomainSet.normalize(value).map(RemoteMatch.domain)
        case .address: return IPNetwork(value) != nil ? .address(value) : nil
        }
    }

    private func save() {
        guard let remote else {
            problem = remoteKind == .address ? "Enter an IP address like 203.0.113.7 or a network like 10.0.0.0/8." : "Enter a valid \(remoteKind.rawValue.lowercased())."
            return
        }
        guard let ports = PortMatch.parse(portText) else {
            problem = "Ports look like 443, 80, 443 or 8000-8100."
            return
        }
        var final = rule
        final.remote = remote
        final.ports = ports
        final.codeRequirement = pinSignature ? signatureRequirement : nil
        switch validity {
        case .forever: final.expiration = .never
        case .until: final.expiration = .date(untilDate)
        case .keep: break
        }
        Task {
            if await model.save(final) { dismiss() }
        }
    }
}
