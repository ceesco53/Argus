import Foundation

/// A compact set of hostnames for blocklists.
///
/// Entries are stored as sorted 64-bit FNV-1a hashes rather than strings: a million-entry
/// threat list costs ~8 MB instead of ~100 MB, which matters inside the network extension.
/// `exact` entries match a hostname only; `suffix` entries also match every subdomain.
public struct DomainSet: Sendable, Equatable {
    public private(set) var exact: [UInt64]
    public private(set) var suffix: [UInt64]

    public enum Match: Equatable, Sendable {
        case exact
        case suffix(String)
    }

    public init(exact: some Sequence<String> = [String](), suffixes: some Sequence<String> = [String]()) {
        self.exact = DomainSet.sortedHashes(exact)
        self.suffix = DomainSet.sortedHashes(suffixes)
    }

    init(exactHashes: [UInt64], suffixHashes: [UInt64]) {
        exact = exactHashes
        suffix = suffixHashes
    }

    public var count: Int { exact.count + suffix.count }
    public var isEmpty: Bool { exact.isEmpty && suffix.isEmpty }

    public func match(_ host: String) -> Match? {
        let bytes = Array(host.lowercased().utf8)
        var end = bytes.count
        if end > 0, bytes[end - 1] == UInt8(ascii: ".") { end -= 1 }
        guard end > 0 else { return nil }
        let name = bytes[0..<end]
        if exact.sortedContains(DomainSet.hash(name)) { return .exact }
        guard !suffix.isEmpty else { return nil }
        var start = name.startIndex
        while start < name.endIndex {
            let candidate = name[start...]
            if suffix.sortedContains(DomainSet.hash(candidate)) {
                return .suffix(String(decoding: candidate, as: UTF8.self))
            }
            guard let dot = candidate.firstIndex(of: UInt8(ascii: ".")) else { break }
            start = dot + 1
        }
        return nil
    }

    /// Lower-cases, strips wildcard prefixes and trailing dots, and rejects anything that
    /// is not a plausible hostname. Returns nil for entries a blocklist should ignore.
    public static func normalize(_ raw: some StringProtocol) -> String? {
        var s = Substring(raw.lowercased())
        while s.hasPrefix("*.") || s.hasPrefix(".") { s = s.drop { $0 == "*" || $0 == "." } }
        while s.hasSuffix(".") { s = s.dropLast() }
        guard !s.isEmpty, s.count <= 253, s.contains(".") || s == "localhost" else { return nil }
        for scalar in s.unicodeScalars {
            switch scalar {
            case "a"..."z", "0"..."9", "-", ".", "_": continue
            default: return nil
            }
        }
        return String(s)
    }

    static func hash(_ bytes: some Sequence<UInt8>) -> UInt64 {
        var hash: UInt64 = 0xcbf2_9ce4_8422_2325
        for byte in bytes {
            hash ^= UInt64(byte)
            hash &*= 0x0000_0100_0000_01B3
        }
        return hash
    }

    static func hash(_ string: String) -> UInt64 { hash(string.utf8) }

    private static func sortedHashes(_ names: some Sequence<String>) -> [UInt64] {
        var hashes = names.map { hash($0.lowercased()) }
        hashes.sort()
        return hashes.uniqued()
    }
}

extension Array where Element: Equatable {
    /// Removes adjacent duplicates from a sorted array.
    func uniqued() -> [Element] {
        var result: [Element] = []
        result.reserveCapacity(count)
        for element in self where result.last != element { result.append(element) }
        return result
    }
}

/// The compiled, matchable form of a blocklist: hostnames plus address ranges.
public struct CompiledBlocklist: Sendable, Equatable {
    public var domains: DomainSet
    public var addresses: IPRangeSet

    public init(domains: DomainSet = DomainSet(), addresses: IPRangeSet = IPRangeSet()) {
        self.domains = domains
        self.addresses = addresses
    }

    public var isEmpty: Bool { domains.isEmpty && addresses.isEmpty }

    // MARK: Binary persistence

    private static let magic: UInt32 = 0x4152_4731 // "ARG1"

    public func serialized() -> Data {
        var data = Data()
        func put<T: FixedWidthInteger>(_ value: T) { withUnsafeBytes(of: value.littleEndian) { data.append(contentsOf: $0) } }
        put(CompiledBlocklist.magic)
        put(UInt64(domains.exact.count)); domains.exact.forEach(put)
        put(UInt64(domains.suffix.count)); domains.suffix.forEach(put)
        put(UInt64(addresses.v4.count)); addresses.v4.forEach { put($0.lowerBound); put($0.upperBound) }
        put(UInt64(addresses.v6.count)); addresses.v6.forEach { put($0.lowerBound); put($0.upperBound) }
        return data
    }

    public init?(serialized data: Data) {
        var offset = data.startIndex
        func get<T: FixedWidthInteger>(_: T.Type) -> T? {
            let size = MemoryLayout<T>.size
            guard offset + size <= data.endIndex else { return nil }
            var value = T.zero
            withUnsafeMutableBytes(of: &value) { $0.copyBytes(from: data[offset..<offset + size]) }
            offset += size
            return T(littleEndian: value)
        }
        func array<T: FixedWidthInteger>(_: T.Type) -> [T]? {
            guard let count = get(UInt64.self), count < 50_000_000 else { return nil }
            var result: [T] = []
            result.reserveCapacity(Int(count))
            for _ in 0..<count { guard let v = get(T.self) else { return nil }; result.append(v) }
            return result
        }
        func ranges<T: FixedWidthInteger>(_: T.Type) -> [ClosedRange<T>]? {
            guard let count = get(UInt64.self), count < 50_000_000 else { return nil }
            var result: [ClosedRange<T>] = []
            for _ in 0..<count {
                guard let lo = get(T.self), let hi = get(T.self), lo <= hi else { return nil }
                result.append(lo...hi)
            }
            return result
        }
        guard get(UInt32.self) == CompiledBlocklist.magic,
              let exact = array(UInt64.self), let suffix = array(UInt64.self),
              let v4 = ranges(UInt32.self), let v6 = ranges(UInt128.self)
        else { return nil }
        domains = DomainSet(exactHashes: exact, suffixHashes: suffix)
        addresses = IPRangeSet(v4: v4, v6: v6)
    }
}
