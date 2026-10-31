import Foundation

/// Limits on what one sync may remove, so a mistake (syncing from the wrong copy of the
/// configuration, say) can't wipe out rules on every Mac.
public enum SyncSafety {
    /// Removing more than five items, and more than a fifth of them, at once needs the user's say-so.
    public static func needsConfirmation(removing count: Int, of total: Int) -> Bool {
        count > 5 && Double(count) > Double(total) * 0.2
    }
}
