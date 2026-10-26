import ArgusKit
import SwiftUI

/// Every recent change to rules, profiles, blocklists and settings, each undoable.
struct RecentChangesView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var changes: [ChangeRecord] = []

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Recent Changes").font(.title2.weight(.semibold))
                    Text("Undo any of them. Undoing one change leaves later ones alone.").font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(20)
            Divider()
            if changes.isEmpty {
                ContentUnavailableView("No changes yet", systemImage: "clock.arrow.circlepath",
                                       description: Text("Changes you make to rules, profiles, blocklists and settings appear here."))
                    .frame(maxHeight: .infinity)
            } else {
                List(changes) { change in
                    HStack(spacing: 10) {
                        Image(systemName: change.isUndone ? "arrow.uturn.backward.circle" : "circle.fill")
                            .font(change.isUndone ? .body : .system(size: 7))
                            .foregroundStyle(change.isUndone ? .secondary : Color.accentColor)
                            .frame(width: 16)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(change.summary).strikethrough(change.isUndone).lineLimit(2)
                            Text(change.date.formatted(date: .abbreviated, time: .shortened)).font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        if change.isUndone {
                            Text("Undone").font(.caption).foregroundStyle(.secondary)
                        } else {
                            Button("Undo") {
                                Task {
                                    await model.undo(change.id)
                                    changes = await model.recentChanges()
                                }
                            }
                        }
                    }
                    .padding(.vertical, 3)
                }
                .listStyle(.inset)
            }
            Divider()
            HStack {
                Text("Kept while Argus's engine is running.").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
            .padding(14)
        }
        .frame(width: 600, height: 540)
        .task { changes = await model.recentChanges() }
    }
}
