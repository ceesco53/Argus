import Foundation

/// Narrows down which of the servers Argus blocked a page actually needs, by letting some of them
/// through, reloading, and asking whether the page works.
///
/// First everything blocked is let through, to make sure Argus is the cause at all. A page that
/// gets further that way may ask for more that Argus blocks, so those join the test until nothing
/// new turns up. Then half of the suspects at a time: if the page works with one half, the culprit
/// is in it; if it works with neither half alone, it needs servers from both and the search stops
/// there.
public struct CulpritSearch: Sendable, Equatable {
    public enum Outcome: Sendable, Equatable {
        /// Letting these through makes the page work.
        case found([String])
        /// The page didn't work even with everything let through, so Argus isn't what breaks it.
        case notArgus
    }

    private enum Stage: Sendable, Equatable { case everything, firstHalf, secondHalf }

    /// Servers that may be the culprit.
    public private(set) var suspects: [String]
    /// What's let through for the current test.
    public private(set) var testing: [String]
    public private(set) var outcome: Outcome?
    /// Which test this is, from 1.
    public private(set) var step = 1
    private var stage = Stage.everything

    /// Whether the current test lets through everything Argus blocked (as opposed to some suspects).
    public var isTestingEverything: Bool { outcome == nil && stage == .everything }

    /// nil when nothing was blocked, so there's nothing to search.
    public init?(blocked: [String]) {
        var seen = Set<String>()
        let unique = blocked.filter { seen.insert($0).inserted }
        guard !unique.isEmpty else { return nil }
        suspects = unique
        testing = unique
    }

    /// Whether the page worked with `testing` let through. `newlyBlocked`: servers Argus blocked
    /// during the test that weren't suspects yet.
    public mutating func record(pageWorked: Bool, newlyBlocked: [String] = []) {
        guard outcome == nil else { return }
        step += 1
        switch stage {
        case .everything:
            var seen = Set(suspects)
            let more = newlyBlocked.filter { seen.insert($0).inserted }
            if pageWorked {
                narrow()
            } else if !more.isEmpty {
                // The page got further and asked for more: let that through too before ruling Argus out.
                suspects += more
                testing = suspects
            } else {
                outcome = .notArgus
                testing = []
            }
        case .firstHalf:
            if pageWorked {
                suspects = testing
                narrow()
            } else {
                stage = .secondHalf
                testing = Array(suspects.dropFirst(suspects.count / 2))
            }
        case .secondHalf:
            if pageWorked {
                suspects = testing
                narrow()
            } else {
                // Neither half alone: the page needs servers from both.
                outcome = .found(suspects)
                testing = suspects
            }
        }
    }

    private mutating func narrow() {
        if suspects.count == 1 {
            outcome = .found(suspects)
            testing = suspects
        } else {
            stage = .firstHalf
            testing = Array(suspects.prefix(suspects.count / 2))
        }
    }
}
