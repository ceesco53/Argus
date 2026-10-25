import ArgusKit
import CoreLocation
import Foundation
import Observation

struct Country: Hashable, Identifiable, Sendable {
    let code: String

    var id: String { code }
    var name: String { Locale.current.localizedString(forRegionCode: code) ?? code }
    var flag: String {
        code.unicodeScalars.compactMap { UnicodeScalar(127_397 + $0.value) }.map(String.init).joined()
    }
    var coordinate: CLLocationCoordinate2D? { GeoLocator.coordinates[code] }
}

/// Maps server addresses to the country they're registered in, using the public statistics
/// files of the five regional internet registries. Lookups never leave the Mac.
@MainActor @Observable
final class GeoLocator {
    enum Status: Equatable {
        case missing
        case working
        case ready(updated: Date, ranges: Int)
        case failed(String)
    }

    private(set) var status: Status = .missing
    @ObservationIgnored private var table = IPRangeTable<UInt16>()

    nonisolated static let sources = [
        "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
        "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
        "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
        "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
        "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
    ].compactMap(URL.init(string:))

    nonisolated static var cacheURL: URL {
        ArgusPaths.supportDirectory().appendingPathComponent("Location/registry.bin")
    }

    var isReady: Bool { if case .ready = status { true } else { false } }

    func load() async {
        let url = GeoLocator.cacheURL
        let loaded = await Task.detached { () -> (IPRangeTable<UInt16>, Date)? in
            guard let data = try? Data(contentsOf: url), let table = GeoLocator.decode(data) else { return nil }
            let date = (try? url.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? Date()
            return (table, date)
        }.value
        if let (table, date) = loaded {
            self.table = table
            status = .ready(updated: date, ranges: table.count)
        }
    }

    func update() async {
        status = .working
        do {
            let table = try await Task.detached { try await GeoLocator.download() }.value
            self.table = table
            status = .ready(updated: Date(), ranges: table.count)
        } catch {
            status = .failed(error.localizedDescription)
        }
    }

    func country(for address: String?) -> Country? {
        guard let address, let ip = IPAddress(address), !ip.isLocalNetwork, let packed = table.lookup(ip) else { return nil }
        return Country(code: String(UnicodeScalar(UInt8(packed >> 8))) + String(UnicodeScalar(UInt8(packed & 0xFF))))
    }

    func country(for connection: ConnectionRecord) -> Country? {
        connection.addresses.lazy.compactMap { self.country(for: $0) }.first
    }

    // MARK: Building the table

    nonisolated private static func download() async throws -> IPRangeTable<UInt16> {
        var v4: [IPRangeTable<UInt16>.Entry<UInt32>] = []
        var v6: [IPRangeTable<UInt16>.Entry<UInt128>] = []
        try await withThrowingTaskGroup(of: Data.self) { group in
            for url in sources {
                group.addTask {
                    let (data, response) = try await URLSession.shared.data(from: url)
                    if let http = response as? HTTPURLResponse, http.statusCode >= 400 {
                        throw URLError(.badServerResponse)
                    }
                    return data
                }
            }
            for try await data in group {
                let (a, b) = parse(String(decoding: data, as: UTF8.self))
                v4 += a
                v6 += b
            }
        }
        let table = IPRangeTable(v4: merge(v4), v6: merge(v6))
        let url = cacheURL
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try encode(table).write(to: url, options: .atomic)
        return table
    }

    /// Lines look like `apnic|JP|ipv4|1.0.16.0|4096|20110412|allocated`.
    nonisolated static func parse(_ text: String) -> ([IPRangeTable<UInt16>.Entry<UInt32>], [IPRangeTable<UInt16>.Entry<UInt128>]) {
        var v4: [IPRangeTable<UInt16>.Entry<UInt32>] = []
        var v6: [IPRangeTable<UInt16>.Entry<UInt128>] = []
        for line in text.split(separator: "\n") where !line.hasPrefix("#") {
            let f = line.split(separator: "|", omittingEmptySubsequences: false)
            guard f.count >= 7, f[1].count == 2, f[1] != "ZZ", f[6] == "allocated" || f[6] == "assigned" else { continue }
            let code = f[1].uppercased().utf8.map { UInt16($0) }
            let packed = code[0] << 8 | code[1]
            if f[2] == "ipv4", case .v4(let start)? = IPAddress(f[3]), let count = UInt32(f[4]), count > 0 {
                v4.append(.init(lower: start, upper: start &+ (count - 1), value: packed))
            } else if f[2] == "ipv6", let prefix = Int(f[4]), let network = IPNetwork("\(f[3])/\(prefix)"),
                      case .v6(let lo) = network.lowerBound, case .v6(let hi) = network.upperBound {
                v6.append(.init(lower: lo, upper: hi, value: packed))
            }
        }
        return (v4, v6)
    }

    /// Joins neighbouring ranges registered to the same country.
    nonisolated static func merge<B: FixedWidthInteger>(_ entries: [IPRangeTable<UInt16>.Entry<B>]) -> [IPRangeTable<UInt16>.Entry<B>] {
        var result: [IPRangeTable<UInt16>.Entry<B>] = []
        for entry in entries.sorted(by: { $0.lower < $1.lower }) {
            if let last = result.last, last.value == entry.value, last.upper != .max, entry.lower <= last.upper + 1 {
                result[result.count - 1] = .init(lower: last.lower, upper: max(last.upper, entry.upper), value: last.value)
            } else if let last = result.last, entry.lower <= last.upper {
                continue // overlapping registrations; keep the first
            } else {
                result.append(entry)
            }
        }
        return result
    }

    nonisolated static func encode(_ table: IPRangeTable<UInt16>) -> Data {
        var data = Data("AGEO".utf8)
        func put<T: FixedWidthInteger>(_ value: T) { Swift.withUnsafeBytes(of: value.littleEndian) { data.append(contentsOf: $0) } }
        put(UInt32(table.v4.count))
        for e in table.v4 { put(e.lower); put(e.upper); put(e.value) }
        put(UInt32(table.v6.count))
        for e in table.v6 { put(e.lower); put(e.upper); put(e.value) }
        return data
    }

    nonisolated static func decode(_ data: Data) -> IPRangeTable<UInt16>? {
        guard data.prefix(4) == Data("AGEO".utf8) else { return nil }
        var offset = data.startIndex + 4
        func get<T: FixedWidthInteger>(_: T.Type) -> T? {
            let size = MemoryLayout<T>.size
            guard offset + size <= data.endIndex else { return nil }
            var value = T.zero
            withUnsafeMutableBytes(of: &value) { $0.copyBytes(from: data[offset..<offset + size]) }
            offset += size
            return T(littleEndian: value)
        }
        guard let n4 = get(UInt32.self) else { return nil }
        var v4: [IPRangeTable<UInt16>.Entry<UInt32>] = []
        v4.reserveCapacity(Int(n4))
        for _ in 0..<n4 {
            guard let lo = get(UInt32.self), let hi = get(UInt32.self), let cc = get(UInt16.self) else { return nil }
            v4.append(.init(lower: lo, upper: hi, value: cc))
        }
        guard let n6 = get(UInt32.self) else { return nil }
        var v6: [IPRangeTable<UInt16>.Entry<UInt128>] = []
        v6.reserveCapacity(Int(n6))
        for _ in 0..<n6 {
            guard let lo = get(UInt128.self), let hi = get(UInt128.self), let cc = get(UInt16.self) else { return nil }
            v6.append(.init(lower: lo, upper: hi, value: cc))
        }
        return IPRangeTable(v4: v4, v6: v6)
    }

    // MARK: Map coordinates

    /// A representative point per country: its principal time zone city from the system's zone.tab.
    nonisolated static let coordinates: [String: CLLocationCoordinate2D] = {
        var result: [String: CLLocationCoordinate2D] = [:]
        for entry in zoneEntries where result[entry.country] == nil { result[entry.country] = entry.coordinate }
        return result
    }()

    /// Where this Mac probably is, from its time zone. No location permission needed.
    nonisolated static var home: CLLocationCoordinate2D? {
        let zone = TimeZone.current.identifier
        return zoneEntries.first { $0.zone == zone }?.coordinate
            ?? Locale.current.region.flatMap { coordinates[$0.identifier] }
    }

    nonisolated private static let zoneEntries: [(country: String, coordinate: CLLocationCoordinate2D, zone: String)] = {
        guard let text = try? String(contentsOfFile: "/usr/share/zoneinfo/zone.tab", encoding: .utf8) else { return [] }
        return text.split(separator: "\n").compactMap { line in
            guard !line.hasPrefix("#") else { return nil }
            let fields = line.split(separator: "\t")
            guard fields.count >= 3, let coordinate = parseISO6709(fields[1]) else { return nil }
            return (String(fields[0]), coordinate, String(fields[2]))
        }
    }()

    /// "+4230+00131" or "+404251-0740023" → degrees.
    nonisolated static func parseISO6709(_ text: Substring) -> CLLocationCoordinate2D? {
        guard let split = text.dropFirst().firstIndex(where: { $0 == "+" || $0 == "-" }) else { return nil }
        func degrees(_ part: Substring, degreeDigits: Int) -> Double? {
            let sign: Double = part.first == "-" ? -1 : 1
            let digits = part.dropFirst()
            guard digits.count >= degreeDigits + 2, let d = Double(digits.prefix(degreeDigits)) else { return nil }
            let rest = digits.dropFirst(degreeDigits)
            let minutes = Double(rest.prefix(2)) ?? 0
            let seconds = Double(rest.dropFirst(2).prefix(2)) ?? 0
            return sign * (d + minutes / 60 + seconds / 3600)
        }
        guard let lat = degrees(text[..<split], degreeDigits: 2), let lon = degrees(text[split...], degreeDigits: 3) else { return nil }
        return CLLocationCoordinate2D(latitude: lat, longitude: lon)
    }
}
