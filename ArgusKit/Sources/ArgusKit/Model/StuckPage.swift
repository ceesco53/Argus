import Foundation

/// The processes a browser runs its pages in: WebKit's web content process (Safari's tabs), a
/// Chromium renderer, Firefox's content process.
public enum PageProcesses {
    public static func isPageProcess(path: String) -> Bool {
        let name = (path as NSString).lastPathComponent
        return name.hasPrefix("com.apple.WebKit.WebContent") || name.hasSuffix(" Helper (Renderer)") || name == "plugin-container"
    }

    /// Processor time each page process working for one of `owners` (the browser's own pids) has
    /// used so far, in seconds.
    public static func cpuTimes(workingFor owners: Set<Int32>) -> [Int32: TimeInterval] {
        guard !owners.isEmpty else { return [:] }
        var times: [Int32: TimeInterval] = [:]
        for pid in ProcessLookup.allPIDs() where !owners.contains(pid) {
            guard let owner = ProcessLookup.responsiblePID(for: pid), owners.contains(owner),
                  let path = ProcessLookup.path(pid: pid), isPageProcess(path: path),
                  let time = ProcessLookup.cpuTime(pid: pid) else { continue }
            times[pid] = time
        }
        return times
    }
}

/// Notices a page stuck in its own script: a page process using a whole processor core, sample
/// after sample. Reloading such a tab doesn't help, since the page loads again in the same stuck
/// process; and while it's stuck it never gets as far as asking for the servers it's missing, so
/// a page check can't see them.
public struct StuckPageWatch: Sendable, Equatable {
    /// Share of one core that counts as flat out.
    public static let busyShare = 0.85
    /// How long a page process has to stay flat out to count as stuck.
    public static let stuckAfter: TimeInterval = 6

    private var lastTime: TimeInterval?
    private var lastCPU: [Int32: TimeInterval] = [:]
    /// When each page process that's flat out started being so.
    private var busySince: [Int32: TimeInterval] = [:]

    /// Page processes stuck as of the latest sample.
    public private(set) var stuck: Set<Int32> = []

    public init() {}

    /// Adds a sample: when it was taken (seconds on a clock that only goes forward) and the
    /// processor time each page process has used so far.
    public mutating func record(at time: TimeInterval, cpu: [Int32: TimeInterval]) {
        defer {
            lastTime = time
            lastCPU = cpu
            stuck = Set(busySince.filter { time - $0.value >= StuckPageWatch.stuckAfter }.keys)
        }
        guard let lastTime, time > lastTime else {
            busySince = [:]
            return
        }
        let interval = time - lastTime
        var busy: [Int32: TimeInterval] = [:]
        for (pid, used) in cpu {
            guard let before = lastCPU[pid], (used - before) / interval >= StuckPageWatch.busyShare else { continue }
            busy[pid] = busySince[pid] ?? lastTime
        }
        busySince = busy
    }
}
