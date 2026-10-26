import Foundation

/// Round, evenly spaced axis values for charts.
public enum ChartTicks {
    /// Values at a round step (1, 2 or 5 times a power of ten) that cover `lower...upper`,
    /// with the number of intervals closest to `desiredCount`.
    public static func values(covering lower: Double, _ upper: Double, desiredCount: Int) -> [Double] {
        guard lower.isFinite, upper.isFinite, desiredCount > 0 else { return [] }
        let low = min(lower, upper)
        let high = max(lower, upper) - low < 1e-9 ? low + 1 : max(lower, upper)
        let magnitude = pow(10, log10((high - low) / Double(desiredCount)).rounded(.down))
        func intervals(_ step: Double) -> Double { (high / step).rounded(.up) - (low / step).rounded(.down) }
        // Largest first, so ties go to the larger step: fewer labels.
        let step = [10, 5, 2, 1, 0.5].map { $0 * magnitude }
            .min { abs(intervals($0) - Double(desiredCount)) < abs(intervals($1) - Double(desiredCount)) } ?? magnitude
        let first = (low / step).rounded(.down), last = (high / step).rounded(.up)
        return stride(from: first, through: last, by: 1).map { $0 * step }
    }

    private static let timeSteps: [TimeInterval] = [
        1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800,
        3600, 7200, 10800, 21600, 43200, 86400, 172_800, 604_800,
    ]

    /// Times at a round step (on the minute, on the hour, at midnight…) within `start...end`,
    /// about `desiredCount` of them.
    public static func dates(from start: Date, to end: Date, desiredCount: Int, timeZone: TimeZone = .current) -> [Date] {
        guard end > start, desiredCount > 0 else { return [] }
        let span = end.timeIntervalSince(start)
        let step = timeSteps.first { span / $0 <= Double(desiredCount) } ?? (span / Double(desiredCount)).rounded(.up)
        // Count in local time, so hours land on the hour and days at midnight.
        let offset = TimeInterval(timeZone.secondsFromGMT(for: start))
        var tick = ((start.timeIntervalSince1970 + offset) / step).rounded(.up) * step - offset
        var ticks: [Date] = []
        while tick <= end.timeIntervalSince1970 + 1e-6 {
            ticks.append(Date(timeIntervalSince1970: tick))
            tick += step
        }
        return ticks
    }
}
