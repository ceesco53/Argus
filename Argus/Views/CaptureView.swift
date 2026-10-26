import ArgusKit
import SwiftUI
import UniformTypeIdentifiers

struct CaptureView: View {
    @Environment(AppModel.self) private var model
    @State private var processPath: String?
    @State private var hostFilter = ""
    @State private var duration: TimeInterval = 300
    @State private var sizeLimit = 200

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                HStack(alignment: .top, spacing: 16) {
                    Image(systemName: "record.circle")
                        .font(.system(size: 34))
                        .foregroundStyle(.red)
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Traffic capture").font(.title2.weight(.semibold))
                        Text("Record what an app sends and receives into a PCAP file you can open in Wireshark or tcpdump. Encrypted connections stay encrypted; you'll see who an app talks to, when and how much.")
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                if !model.isEnforcing {
                    MonitorModeBanner()
                }
                newCapture
                sessions
            }
            .padding(24)
        }
        .navigationTitle("Traffic Capture")
        .task { await model.refreshCaptures() }
    }

    private var newCapture: some View {
        VStack(alignment: .leading, spacing: 12) {
            CardHeader(title: "New capture", symbol: "plus.circle")
            Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 10) {
                GridRow {
                    Text("Program").foregroundStyle(.secondary)
                    Picker("Program", selection: $processPath) {
                        Text("All programs").tag(String?.none)
                        Divider()
                        ForEach(model.processes.values.sorted { $0.identity.name.localizedCaseInsensitiveCompare($1.identity.name) == .orderedAscending }) { process in
                            Text(process.identity.name).tag(String?.some(process.id))
                        }
                    }
                    .labelsHidden()
                }
                GridRow {
                    Text("Server").foregroundStyle(.secondary)
                    TextField("Server", text: $hostFilter, prompt: Text("Optional: part of a hostname or address"))
                        .labelsHidden()
                }
                GridRow {
                    Text("Stop after").foregroundStyle(.secondary)
                    Picker("Duration", selection: $duration) {
                        Text("1 minute").tag(TimeInterval(60))
                        Text("5 minutes").tag(TimeInterval(300))
                        Text("15 minutes").tag(TimeInterval(900))
                        Text("1 hour").tag(TimeInterval(3600))
                        Text("When I stop it").tag(TimeInterval(0))
                    }
                    .labelsHidden()
                }
                GridRow {
                    Text("Size limit").foregroundStyle(.secondary)
                    Picker("Size", selection: $sizeLimit) {
                        Text("50 MB").tag(50)
                        Text("200 MB").tag(200)
                        Text("1 GB").tag(1024)
                    }
                    .labelsHidden()
                }
            }
            HStack {
                Text("Only connections that start after you begin are captured.").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button {
                    let request = CaptureRequest(processPath: processPath, remoteFilter: hostFilter.isEmpty ? nil : hostFilter,
                                                 maxBytes: sizeLimit * 1024 * 1024, duration: duration == 0 ? nil : duration)
                    Task { await model.startCapture(request) }
                } label: {
                    Label("Start Capture", systemImage: "record.circle.fill")
                }
                .buttonStyle(.borderedProminent)
                .tint(.red)
                .disabled(!model.isEnforcing)
            }
        }
        .card()
    }

    private var sessions: some View {
        VStack(alignment: .leading, spacing: 10) {
            CardHeader(title: "Captures", symbol: "doc.on.doc")
            if model.captures.isEmpty {
                Text("No captures yet.").foregroundStyle(.secondary)
            }
            ForEach(model.captures) { session in
                CaptureRow(session: session)
                if session.id != model.captures.last?.id { Divider() }
            }
        }
        .card()
    }
}

private struct CaptureRow: View {
    @Environment(AppModel.self) private var model
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    let session: CaptureSession

    var body: some View {
        HStack(spacing: 12) {
            if session.isActive {
                Circle().fill(.red).frame(width: 10, height: 10)
                    .phaseAnimator(reduceMotion ? [1.0] : [1.0, 0.3]) { content, phase in content.opacity(phase) } animation: { _ in .easeInOut(duration: 0.8) }
                    .accessibilityLabel("Recording")
            } else {
                Image(systemName: "doc.badge.ellipsis").foregroundStyle(.secondary)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(session.processName ?? "All programs").fontWeight(.medium)
                Text(details).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            if session.isActive {
                Button("Stop") { Task { await model.stopCapture(session.id) } }
            } else {
                if let wireshark = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "org.wireshark.Wireshark") {
                    Button("Open in Wireshark") { open(with: wireshark) }
                }
                Button("Save…") { save() }
                Button {
                    Task { await model.deleteCapture(session.id) }
                } label: {
                    Image(systemName: "trash")
                }
                .help("Delete capture")
            }
        }
        .controlSize(.small)
    }

    private var details: String {
        var parts = [session.startedAt.formatted(date: .abbreviated, time: .shortened)]
        if let filter = session.remoteFilter { parts.append("matching “\(filter)”") }
        parts.append("\(session.flowCount) connections")
        parts.append("\(session.packetCount.formatted()) packets")
        parts.append(Formatting.bytes(UInt64(session.fileSize)))
        return parts.joined(separator: " · ")
    }

    private func save() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = session.fileName
        panel.allowedContentTypes = [UTType(filenameExtension: "pcap") ?? .data]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        Task { _ = await model.saveCapture(session.id, to: url) }
    }

    private func open(with application: URL) {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(session.fileName)
        Task {
            if await model.saveCapture(session.id, to: url) {
                _ = try? await NSWorkspace.shared.open([url], withApplicationAt: application, configuration: NSWorkspace.OpenConfiguration())
            }
        }
    }
}
