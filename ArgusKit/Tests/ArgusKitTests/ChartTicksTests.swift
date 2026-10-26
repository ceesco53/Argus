import Foundation
import Testing
@testable import ArgusKit

@Suite struct ChartTicksTests {
    @Test func valuesAreRoundAndCoverTheData() {
        #expect(ChartTicks.values(covering: 0, 97, desiredCount: 4) == [0, 20, 40, 60, 80, 100])
        // Received above zero, sent below: zero is always a tick.
        let mirrored = ChartTicks.values(covering: -1_200_000, 4_700_000, desiredCount: 4)
        #expect(mirrored == [-2_000_000, 0, 2_000_000, 4_000_000, 6_000_000])
        // No traffic still gives a usable axis.
        let empty = ChartTicks.values(covering: 0, 0, desiredCount: 4)
        #expect(empty.first == 0 && empty.last == 1 && empty.count > 2)
    }

    @Test func timesLandOnRoundMoments() throws {
        let utc = try #require(TimeZone(identifier: "UTC"))
        let start = Date(timeIntervalSince1970: 1_000_000_007) // 01:46:47 UTC
        let live = ChartTicks.dates(from: start, to: start.addingTimeInterval(120), desiredCount: 6, timeZone: utc)
        #expect(live.count == 4)
        #expect(live.allSatisfy { Int($0.timeIntervalSince1970) % 30 == 0 })

        // A day of data: every six hours, counted in local time rather than UTC.
        let tokyo = try #require(TimeZone(identifier: "Asia/Tokyo"))
        let day = ChartTicks.dates(from: start, to: start.addingTimeInterval(86_400), desiredCount: 6, timeZone: tokyo)
        #expect(!day.isEmpty && day.count <= 6)
        let offset = tokyo.secondsFromGMT(for: start)
        #expect(day.allSatisfy { (Int($0.timeIntervalSince1970) + offset) % 21_600 == 0 })
    }
}
