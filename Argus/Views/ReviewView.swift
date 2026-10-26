import ArgusKit
import SwiftUI

/// After learning (or silent modes), decide about every app that used the network without a rule.
struct ReviewView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var expanded: Set<String> = []

    var body: some View {
        let items = model.reviewItems
        let signed = items.filter { $0.process.identity.signature.isTrustedPublisher }
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 10) {
                HStack(alignment: .top, spacing: 14) {
                    MascotView(size: 64)
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Review what your apps did").font(.title2.weight(.semibold))
                        Text("These apps used the network without a rule. Trust the ones you know; Argus will keep asking about anything new.")
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                if let until = model.learningUntil {
                    HStack {
                        Label("Still learning until \(until.formatted(date: .abbreviated, time: .shortened))", systemImage: "graduationcap")
                            .font(.callout)
                        Spacer()
                        Button("End Learning Now") { Task { await model.endLearning() } }
                    }
                }
                if !items.isEmpty {
                    HStack {
                        Button("Trust \(signed.count) Signed by Apple or Known Developers") { Task { await model.trust(signed) } }
                            .disabled(signed.isEmpty)
                            .help("Apps signed by Apple, the App Store or a registered developer")
                        Button("Trust All \(items.count)") { Task { await model.trust(items) } }
                        Spacer()
                    }
                }
            }
            .padding(20)
            Divider()
            if items.isEmpty {
                ContentUnavailableView("Nothing to review", systemImage: "checkmark.seal",
                                       description: Text("Every app that has used the network has a rule."))
                    .frame(maxHeight: .infinity)
            } else {
                List {
                    ForEach(items) { item in
                        row(item)
                    }
                }
                .listStyle(.inset)
            }
            Divider()
            HStack {
                Text("Trust lets an app connect anywhere, but only while it keeps its code signature.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
            .padding(14)
        }
        .frame(width: 700, height: 640)
    }

    private func row(_ item: AppModel.ReviewItem) -> some View {
        let identity = item.process.identity
        let isExpanded = expanded.contains(item.id)
        return VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 10) {
                AppIconView(identity: identity, size: 30)
                VStack(alignment: .leading, spacing: 2) {
                    Text(identity.name).fontWeight(.medium)
                    HStack(spacing: 8) {
                        SignatureBadge(kind: identity.signature)
                        if item.destinations.isEmpty {
                            Text(Formatting.bytes(item.process.totalBytes)).font(.caption).foregroundStyle(.secondary)
                        } else {
                            Button {
                                if isExpanded { expanded.remove(item.id) } else { expanded.insert(item.id) }
                            } label: {
                                HStack(spacing: 3) {
                                    Text("\(item.destinations.count) server\(item.destinations.count == 1 ? "" : "s") · \(Formatting.bytes(item.process.totalBytes))")
                                    Image(systemName: isExpanded ? "chevron.up" : "chevron.down").imageScale(.small)
                                }
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                            .accessibilityLabel(isExpanded ? "Hide servers" : "Show \(item.destinations.count) servers")
                        }
                    }
                }
                Spacer()
                Button("Trust") { Task { await model.trust([item]) } }
                    .buttonStyle(.borderedProminent)
                    .help("Allow \(identity.name) to connect anywhere")
                Menu("More") {
                    Button("Allow Only These \(item.destinations.count) Servers") { Task { await model.allowWhatItUsed(item) } }
                    Button("Block \(identity.name)") { Task { await model.block(item) } }
                    Divider()
                    Button("Decide Later") { model.skipReview(item) }
                }
                .fixedSize()
            }
            if isExpanded {
                VStack(alignment: .leading, spacing: 3) {
                    ForEach(item.destinations.prefix(12)) { destination in
                        HStack {
                            Text(destination.remote).font(.caption).lineLimit(1)
                            Spacer()
                            Text(Formatting.bytes(destination.totalBytes)).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    if item.destinations.count > 12 {
                        Text("and \(item.destinations.count - 12) more").font(.caption).foregroundStyle(.tertiary)
                    }
                }
                .padding(.leading, 40)
            }
        }
        .padding(.vertical, 4)
    }
}
