import Darwin
import Foundation

/// An IPv4 or IPv6 address stored as an integer so that ranges compare cheaply.
/// IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are normalised to `.v4`.
public enum IPAddress: Hashable, Sendable, Comparable, CustomStringConvertible, Codable {
    case v4(UInt32)
    case v6(UInt128)

    public init?(_ text: some StringProtocol) {
        var s = text.trimmingCharacters(in: .whitespaces)
        if s.hasPrefix("["), s.hasSuffix("]") { s = String(s.dropFirst().dropLast()) }
        if let zone = s.firstIndex(of: "%") { s = String(s[..<zone]) }
        var v4 = in_addr()
        if inet_pton(AF_INET, s, &v4) == 1 {
            self = .v4(UInt32(bigEndian: v4.s_addr))
            return
        }
        var v6 = in6_addr()
        guard inet_pton(AF_INET6, s, &v6) == 1 else { return nil }
        self.init(in6: v6)
    }

    public init(in6 address: in6_addr) {
        let value = withUnsafeBytes(of: address) { raw in raw.reduce(UInt128(0)) { ($0 << 8) | UInt128($1) } }
        self = IPAddress.normalized(v6: value)
    }

    public init?(bytes: some Collection<UInt8>) {
        switch bytes.count {
        case 4: self = .v4(bytes.reduce(0) { ($0 << 8) | UInt32($1) })
        case 16: self = IPAddress.normalized(v6: bytes.reduce(UInt128(0)) { ($0 << 8) | UInt128($1) })
        default: return nil
        }
    }

    private static func normalized(v6 value: UInt128) -> IPAddress {
        value >> 32 == 0xFFFF ? .v4(UInt32(truncatingIfNeeded: value)) : .v6(value)
    }

    public var isIPv4: Bool { if case .v4 = self { true } else { false } }

    public var bytes: [UInt8] {
        switch self {
        case .v4(let v): return (0..<4).reversed().map { UInt8(truncatingIfNeeded: v >> (UInt32($0) * 8)) }
        case .v6(let v): return (0..<16).reversed().map { UInt8(truncatingIfNeeded: v >> (UInt128($0) * 8)) }
        }
    }

    public var description: String {
        switch self {
        case .v4(let v):
            return "\(v >> 24).\(v >> 16 & 0xFF).\(v >> 8 & 0xFF).\(v & 0xFF)"
        case .v6:
            var address = in6_addr()
            withUnsafeMutableBytes(of: &address) { $0.copyBytes(from: bytes) }
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            _ = inet_ntop(AF_INET6, &address, &buffer, socklen_t(buffer.count))
            return buffer.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
        }
    }

    // MARK: Classification

    public var isLoopback: Bool {
        switch self {
        case .v4(let v): v >> 24 == 127
        case .v6(let v): v == 1
        }
    }

    public var isLinkLocal: Bool {
        switch self {
        case .v4(let v): v >> 16 == 0xA9FE
        case .v6(let v): v >> 118 == 0x3FA
        }
    }

    public var isPrivate: Bool {
        switch self {
        case .v4(let v):
            v >> 24 == 10 || v >> 20 == 0xAC1 || v >> 16 == 0xC0A8 || v >> 22 == 0x191
        case .v6(let v):
            v >> 121 == 0x7E
        }
    }

    public var isMulticast: Bool {
        switch self {
        case .v4(let v): v >> 28 == 0xE
        case .v6(let v): v >> 120 == 0xFF
        }
    }

    public var isBroadcast: Bool { self == .v4(.max) }

    public var isUnspecified: Bool {
        switch self {
        case .v4(let v): v == 0
        case .v6(let v): v == 0
        }
    }

    /// Addresses that never leave the local network segment.
    public var isLocalNetwork: Bool {
        isPrivate || isLinkLocal || isMulticast || isBroadcast || isLoopback
    }

    // MARK: Codable (as text, so state files stay readable)

    public init(from decoder: Decoder) throws {
        let text = try decoder.singleValueContainer().decode(String.self)
        guard let address = IPAddress(text) else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Invalid IP address \(text)"))
        }
        self = address
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }
}

/// A CIDR network such as `10.0.0.0/8` or `2001:db8::/32`. A bare address is a /32 or /128.
public struct IPNetwork: Hashable, Sendable, CustomStringConvertible {
    public let address: IPAddress
    public let prefixLength: Int

    public init?(_ text: some StringProtocol) {
        let parts = text.trimmingCharacters(in: .whitespaces).split(separator: "/", maxSplits: 1)
        guard let first = parts.first, let address = IPAddress(first) else { return nil }
        let maxPrefix = address.isIPv4 ? 32 : 128
        var prefix = maxPrefix
        if parts.count == 2 {
            guard let p = Int(parts[1]), (0...maxPrefix).contains(p) else { return nil }
            prefix = p
        }
        self.init(address: address, prefixLength: prefix)
    }

    public init(address: IPAddress, prefixLength: Int) {
        self.prefixLength = prefixLength
        switch address {
        case .v4(let v): self.address = .v4(v & IPNetwork.mask32(prefixLength))
        case .v6(let v): self.address = .v6(v & IPNetwork.mask128(prefixLength))
        }
    }

    static func mask32(_ prefix: Int) -> UInt32 { prefix == 0 ? 0 : UInt32.max << UInt32(32 - prefix) }
    static func mask128(_ prefix: Int) -> UInt128 { prefix == 0 ? 0 : UInt128.max << UInt128(128 - prefix) }

    public var isSingleAddress: Bool { prefixLength == (address.isIPv4 ? 32 : 128) }

    public var lowerBound: IPAddress { address }

    public var upperBound: IPAddress {
        switch address {
        case .v4(let v): .v4(v | ~IPNetwork.mask32(prefixLength))
        case .v6(let v): .v6(v | ~IPNetwork.mask128(prefixLength))
        }
    }

    public func contains(_ ip: IPAddress) -> Bool {
        switch (address, ip) {
        case let (.v4(net), .v4(value)): value & IPNetwork.mask32(prefixLength) == net
        case let (.v6(net), .v6(value)): value & IPNetwork.mask128(prefixLength) == net
        default: false
        }
    }

    public var description: String { isSingleAddress ? address.description : "\(address)/\(prefixLength)" }
}

/// A sorted, merged set of address ranges answering membership in O(log n).
public struct IPRangeSet: Sendable, Equatable {
    public private(set) var v4: [ClosedRange<UInt32>] = []
    public private(set) var v6: [ClosedRange<UInt128>] = []

    public init() {}

    public init(networks: some Sequence<IPNetwork>) {
        var v4: [ClosedRange<UInt32>] = []
        var v6: [ClosedRange<UInt128>] = []
        for network in networks {
            switch (network.lowerBound, network.upperBound) {
            case let (.v4(lo), .v4(hi)): v4.append(lo...hi)
            case let (.v6(lo), .v6(hi)): v6.append(lo...hi)
            default: break
            }
        }
        self.v4 = IPRangeSet.merge(v4)
        self.v6 = IPRangeSet.merge(v6)
    }

    public init(v4: [ClosedRange<UInt32>], v6: [ClosedRange<UInt128>]) {
        self.v4 = IPRangeSet.merge(v4)
        self.v6 = IPRangeSet.merge(v6)
    }

    public var isEmpty: Bool { v4.isEmpty && v6.isEmpty }
    public var count: Int { v4.count + v6.count }

    public func contains(_ ip: IPAddress) -> Bool {
        switch ip {
        case .v4(let v): IPRangeSet.search(v4, v)
        case .v6(let v): IPRangeSet.search(v6, v)
        }
    }

    static func merge<T: FixedWidthInteger>(_ ranges: [ClosedRange<T>]) -> [ClosedRange<T>] {
        let sorted = ranges.sorted { $0.lowerBound < $1.lowerBound }
        var merged: [ClosedRange<T>] = []
        for range in sorted {
            if let last = merged.last, range.lowerBound <= last.upperBound || (last.upperBound != .max && range.lowerBound == last.upperBound + 1) {
                merged[merged.count - 1] = last.lowerBound...max(last.upperBound, range.upperBound)
            } else {
                merged.append(range)
            }
        }
        return merged
    }

    static func search<T: Comparable>(_ ranges: [ClosedRange<T>], _ value: T) -> Bool {
        var low = 0, high = ranges.count - 1
        while low <= high {
            let mid = (low + high) / 2
            let range = ranges[mid]
            if value < range.lowerBound { high = mid - 1 } else if value > range.upperBound { low = mid + 1 } else { return true }
        }
        return false
    }
}

/// Non-overlapping address ranges mapped to a value; used for the location database.
public struct IPRangeTable<Value: Sendable>: Sendable {
    public struct Entry<Bound: Comparable & Sendable>: Sendable {
        public let lower: Bound
        public let upper: Bound
        public let value: Value

        public init(lower: Bound, upper: Bound, value: Value) {
            self.lower = lower
            self.upper = upper
            self.value = value
        }
    }

    public private(set) var v4: [Entry<UInt32>] = []
    public private(set) var v6: [Entry<UInt128>] = []

    public init(v4: [Entry<UInt32>], v6: [Entry<UInt128>]) {
        self.v4 = v4.sorted { $0.lower < $1.lower }
        self.v6 = v6.sorted { $0.lower < $1.lower }
    }

    public init() {}

    public var count: Int { v4.count + v6.count }

    public func lookup(_ ip: IPAddress) -> Value? {
        switch ip {
        case .v4(let v): IPRangeTable.find(v4, v)
        case .v6(let v): IPRangeTable.find(v6, v)
        }
    }

    private static func find<B>(_ entries: [Entry<B>], _ value: B) -> Value? {
        var low = 0, high = entries.count - 1
        while low <= high {
            let mid = (low + high) / 2
            let entry = entries[mid]
            if value < entry.lower { high = mid - 1 } else if value > entry.upper { low = mid + 1 } else { return entry.value }
        }
        return nil
    }
}
