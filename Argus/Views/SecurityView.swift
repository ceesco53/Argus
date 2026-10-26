import ArgusKit
import SwiftUI

struct SecurityView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                signatures
                packetCapture
                lock
                eventLog
            }
            .padding(24)
        }
        .navigationTitle("Security")
    }

    private func settingToggle(_ title: String, _ detail: String, _ keyPath: WritableKeyPath<FirewallSettings, Bool>) -> some View {
        Toggle(isOn: Binding(get: { model.state.settings[keyPath: keyPath] },
                             set: { value in Task { await model.updateSettings { $0[keyPath: keyPath] = value } } })) {
            Text(title)
            Text(detail)
        }
        .toggleStyle(.switch)
    }

    // MARK: Code signatures

    private var signatures: some View {
        let processes = Array(model.processes.values)
        let counts = Dictionary(grouping: processes, by: \.identity.signature).mapValues(\.count)
        let suspicious = processes.filter { [.unsigned, .invalid, .adHoc, .unknown].contains($0.identity.signature) }
            .sorted { $0.identity.name < $1.identity.name }
        return VStack(alignment: .leading, spacing: 14) {
            CardHeader(title: "Code signatures", symbol: "checkmark.seal.fill")
            Text("Every program's signature is checked when it connects. Rules made from alerts remember the signature, so a program that gets replaced or tampered with can't inherit its rules.")
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            settingToggle("Block programs whose signature changed", "Applies to rules that remember a signature.", \.enforceCodeSignatures)
            HStack(spacing: 10) {
                ForEach([SignatureKind.apple, .appStore, .developerID, .development, .adHoc, .unsigned, .invalid], id: \.self) { kind in
                    VStack(spacing: 2) {
                        Text("\(counts[kind] ?? 0)").font(.title3.weight(.semibold).monospacedDigit())
                            .foregroundStyle(kind.isWarning && (counts[kind] ?? 0) > 0 ? .orange : .primary)
                        Text(kind.displayName).font(.caption2).foregroundStyle(.secondary).multilineTextAlignment(.center)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                    .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 8))
                }
            }
            if !suspicious.isEmpty {
                Text("Worth a look").font(.subheadline.weight(.semibold))
                ForEach(suspicious) { process in
                    HStack(spacing: 10) {
                        AppIconView(identity: process.identity, size: 24)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(process.identity.name)
                            Text(process.id).font(.caption.monospaced()).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                        }
                        Spacer()
                        SignatureBadge(kind: process.identity.signature)
                        Button("Block") {
                            Task { _ = await model.save(Rule(action: .deny, process: .path(process.id), notes: "Blocked from Security: \(process.identity.signature.displayName)")) }
                        }
                        .controlSize(.small)
                    }
                }
            }
        }
        .card()
    }

    // MARK: BPF

    private var packetCapture: some View {
        VStack(alignment: .leading, spacing: 12) {
            CardHeader(title: "Packet sniffing", symbol: "antenna.radiowaves.left.and.right")
            Text("Programs that open a Berkeley Packet Filter device (/dev/bpf) can read every unencrypted packet on this Mac. Argus checks for them every few seconds and warns you.")
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            settingToggle("Watch for packet sniffers", "Warns when a program starts reading raw network traffic.", \.monitorPacketCapture)
            if model.bpfUsers.isEmpty {
                Label("Nothing is reading raw network traffic.", systemImage: "checkmark.circle.fill").foregroundStyle(Color.allowed)
            } else {
                ForEach(model.bpfUsers) { user in
                    HStack(spacing: 10) {
                        Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                        VStack(alignment: .leading, spacing: 1) {
                            Text("\(user.name) (pid \(user.pid))").fontWeight(.medium)
                            Text("\(user.device) · \(user.path) · since \(user.firstSeen.relative)").font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        if user.userID == getuid() {
                            Button("Quit Program") { kill(user.pid, SIGTERM) }.controlSize(.small)
                        }
                    }
                }
            }
            if model.engine == .monitor {
                Text("In monitor mode Argus can only inspect programs running as you. Sniffers started with sudo are detected once the network filter is installed.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .card()
    }

    // MARK: Lock

    private var lock: some View {
        let settings = model.state.settings
        return VStack(alignment: .leading, spacing: 12) {
            CardHeader(title: "Settings lock", symbol: settings.lockEnabled ? "lock.fill" : "lock.open")
            Text("Require an administrator password to change rules, profiles and settings. Useful on shared Macs and for managed employees. Root (for example `sudo argus …` over SSH) can always make changes.")
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            settingToggle("Lock settings", settings.lockEnabled ? (model.isUnlocked ? "Unlocked for this session." : "Locked.") : "Anyone using this Mac can change settings.", \.lockEnabled)
            if settings.lockEnabled {
                settingToggle("Let alerts create rules while locked", "Otherwise alerts can only allow or deny once.", \.alertsAllowedWhenLocked)
                HStack {
                    Spacer()
                    if model.isUnlocked {
                        Button("Lock Now") { model.lock() }
                    } else {
                        Button("Unlock…") { Task { await model.unlock() } }
                    }
                }
            }
        }
        .card()
    }

    // MARK: Events

    private var eventLog: some View {
        VStack(alignment: .leading, spacing: 10) {
            CardHeader(title: "Event log", symbol: "list.bullet.clipboard")
            if model.events.isEmpty {
                Text("Nothing noteworthy has happened.").foregroundStyle(.secondary)
            }
            ForEach(model.events.reversed().prefix(60)) { event in
                HStack(alignment: .top, spacing: 10) {
                    Image(systemName: symbol(for: event.kind))
                        .foregroundStyle(event.isWarning ? .orange : .secondary)
                        .frame(width: 20)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(event.title)
                        if !event.detail.isEmpty {
                            Text(event.detail).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    Spacer()
                    Text(event.date.formatted(date: .abbreviated, time: .shortened)).font(.caption).foregroundStyle(.tertiary)
                }
                .padding(.vertical, 2)
            }
        }
        .card()
    }

    private func symbol(for kind: ActivityEvent.Kind) -> String {
        switch kind {
        case .signatureMismatch, .invalidSignature: "xmark.seal.fill"
        case .packetCapture: "antenna.radiowaves.left.and.right"
        case .profileSwitched: "person.2.crop.square.stack"
        case .ruleGroupUpdated: "arrow.triangle.2.circlepath"
        case .ruleGroupFailed: "exclamationmark.arrow.triangle.2.circlepath"
        case .ruleExpired: "timer"
        case .captureFinished: "record.circle"
        case .protectionChanged: "power"
        case .info: "info.circle"
        case .learningFinished: "graduationcap"
        case .dataUsage: "chart.bar.xaxis"
        }
    }
}
