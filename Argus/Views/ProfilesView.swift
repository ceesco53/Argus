import ArgusKit
import CoreLocation
import SwiftUI

struct ProfilesView: View {
    @Environment(AppModel.self) private var model
    @State private var selection: UUID?

    var body: some View {
        HSplitView {
            list.frame(minWidth: 200, idealWidth: 230, maxWidth: 300)
            detail.frame(minWidth: 420, maxWidth: .infinity)
        }
        .navigationTitle("Profiles")
        .task(id: model.state.profiles.map(\.id)) {
            if selection == nil || model.state.profile(id: selection) == nil {
                selection = model.state.settings.activeProfileID ?? model.state.profiles.first?.id
            }
        }
    }

    private var list: some View {
        VStack(spacing: 0) {
            List(selection: $selection) {
                Section {
                    ForEach(model.state.profiles) { profile in
                        HStack {
                            Label(profile.name, systemImage: profile.symbolName)
                            Spacer()
                            if profile.id == model.state.settings.activeProfileID {
                                Image(systemName: "checkmark.circle.fill").foregroundStyle(Color.allowed).help("Active")
                            }
                        }
                        .tag(profile.id as UUID?)
                    }
                } footer: {
                    Text("Rules can belong to one profile or to all of them. Only the active profile's rules apply.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Divider()
            HStack {
                Button {
                    let profile = Profile(name: "New Profile")
                    Task {
                        await model.save(profile)
                        selection = profile.id
                    }
                } label: {
                    Image(systemName: "plus")
                }
                Button {
                    if let selection { Task { await model.deleteProfile(selection) } }
                    selection = nil
                } label: {
                    Image(systemName: "minus")
                }
                .disabled(selection == nil)
                Spacer()
            }
            .buttonStyle(.borderless)
            .padding(8)
        }
    }

    @ViewBuilder
    private var detail: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                automaticSwitching
                if let id = selection, let profile = model.state.profile(id: id) {
                    ProfileEditor(profile: profile).id(profile.id)
                } else {
                    ContentUnavailableView("No profile selected", systemImage: "person.2.crop.square.stack",
                                           description: Text("Profiles let you use different rules at home, at work or on public Wi-Fi."))
                }
            }
            .padding(24)
        }
    }

    private var automaticSwitching: some View {
        VStack(alignment: .leading, spacing: 10) {
            Toggle(isOn: Binding(get: { model.state.settings.autoSwitchProfiles },
                                 set: { value in Task { await model.updateSettings { $0.autoSwitchProfiles = value } } })) {
                Text("Switch profiles automatically").font(.headline)
                Text("When the Mac joins a network that belongs to a profile, Argus activates it.")
            }
            .toggleStyle(.switch)
            if let network = model.network.current {
                HStack(spacing: 8) {
                    Image(systemName: network.interface.symbolName).foregroundStyle(.tint)
                    Text("Current network: \(network.displayName)")
                    if network.gatewayHardwareAddress == nil {
                        Button("Identify Router") { model.network.requestRouterIdentification() }
                            .buttonStyle(.link)
                            .help("With Local Network access Argus can recognise this network by its router, even when the address is common, like 192.168.1.1.")
                    }
                    if network.ssid == nil, network.interface == .wifi {
                        Button("Show Wi-Fi Name") { LocationPermission.request { model.network.refresh() } }
                            .buttonStyle(.link)
                            .help("macOS only reveals Wi-Fi names to apps with Location Services permission. Argus never uses your location.")
                    }
                }
                .font(.callout)
                .foregroundStyle(.secondary)
            }
        }
        .card()
    }
}

private struct ProfileEditor: View {
    @Environment(AppModel.self) private var model
    @State var profile: Profile

    var body: some View {
        let isActive = model.state.settings.activeProfileID == profile.id
        VStack(alignment: .leading, spacing: 18) {
            HStack(spacing: 14) {
                Image(systemName: profile.symbolName)
                    .font(.system(size: 30))
                    .foregroundStyle(.tint)
                    .frame(width: 56, height: 56)
                    .background(Color.accentColor.opacity(0.14), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                TextField("Name", text: $profile.name)
                    .textFieldStyle(.plain)
                    .font(.title.weight(.semibold))
                    .onSubmit(save)
                Spacer()
                if isActive {
                    Pill(text: "Active", symbol: "checkmark", tint: .allowed)
                } else {
                    Button("Activate") { Task { await model.activateProfile(profile.id) } }
                        .buttonStyle(.borderedProminent)
                }
            }

            VStack(alignment: .leading, spacing: 8) {
                Text("Icon").font(.headline)
                HStack {
                    ForEach(Profile.suggestedSymbols, id: \.self) { symbol in
                        Button {
                            profile.symbolName = symbol
                            save()
                        } label: {
                            Image(systemName: symbol)
                                .frame(width: 30, height: 30)
                                .background(profile.symbolName == symbol ? Color.accentColor.opacity(0.25) : .clear,
                                            in: RoundedRectangle(cornerRadius: 7))
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
            .card()

            VStack(alignment: .leading, spacing: 8) {
                Text("New connections in this profile").font(.headline)
                Picker("Mode", selection: Binding(get: { profile.modeOverride }, set: { profile.modeOverride = $0; save() })) {
                    Text("Use the global setting (\(model.state.settings.mode.displayName))").tag(FilterMode?.none)
                    ForEach(FilterMode.allCases, id: \.self) { Text($0.displayName).tag(FilterMode?.some($0)) }
                }
                .labelsHidden()
                Text((profile.modeOverride ?? model.state.settings.mode).explanation).font(.caption).foregroundStyle(.secondary)
            }
            .card()

            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Text("Networks").font(.headline)
                    Spacer()
                    if let current = model.network.current, !profile.networks.contains(where: { $0.matches(current) }) {
                        Button("Add Current Network") {
                            Task { await model.assign(current, to: profile.id) }
                        }
                    }
                }
                if profile.networks.isEmpty {
                    Text("Add networks to switch to this profile automatically when you join them.")
                        .foregroundStyle(.secondary)
                }
                ForEach(profile.networks, id: \.self) { network in
                    HStack {
                        Image(systemName: network.interface.symbolName).foregroundStyle(.secondary).frame(width: 20)
                        VStack(alignment: .leading) {
                            Text(network.displayName)
                            if let gateway = network.gatewayAddress {
                                Text("Router \(gateway)\(network.gatewayHardwareAddress.map { " (\($0))" } ?? "")")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                        }
                        Spacer()
                        Button {
                            profile.networks.removeAll { $0 == network }
                            save()
                        } label: {
                            Image(systemName: "minus.circle.fill").foregroundStyle(.secondary)
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
            .card()

            let rules = model.state.rules.filter { $0.profileID == profile.id }
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text("Rules only in this profile").font(.headline)
                    Spacer()
                    Text("\(rules.count)").foregroundStyle(.secondary)
                }
                ForEach(rules.prefix(8)) { rule in
                    Text(rule.summary).font(.callout).lineLimit(1)
                }
                Text("To add one, choose this profile under Scope when editing a rule, or tick “Only in this profile” in an alert.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .card()

            TextField("Notes", text: $profile.notes, axis: .vertical)
                .lineLimit(2...5)
                .onSubmit(save)
                .card()
        }
        .onDisappear(perform: save)
    }

    private func save() {
        guard model.state.profile(id: profile.id) != profile else { return }
        Task { await model.save(profile) }
    }
}

/// Wi-Fi names are only readable with Location Services permission on current macOS.
@MainActor
enum LocationPermission {
    private static let manager = CLLocationManager()
    private static var delegate: Delegate?

    static func request(then completion: @escaping @MainActor @Sendable () -> Void) {
        let delegate = Delegate(completion: completion)
        self.delegate = delegate
        manager.delegate = delegate
        manager.requestWhenInUseAuthorization()
    }

    private final class Delegate: NSObject, CLLocationManagerDelegate, @unchecked Sendable {
        let completion: @MainActor @Sendable () -> Void
        init(completion: @escaping @MainActor @Sendable () -> Void) { self.completion = completion }

        nonisolated func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
            Task { @MainActor in self.completion() }
        }
    }
}
