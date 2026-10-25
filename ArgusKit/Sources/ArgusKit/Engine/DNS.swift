import Foundation

/// Just enough of RFC 1035 to learn which hostname an address answer belongs to.
public struct DNSMessage: Sendable {
    public struct Answer: Sendable, Equatable {
        public var name: String
        public var type: UInt16
        public var ttl: UInt32
        public var address: IPAddress?
        public var target: String?
    }

    public var id: UInt16
    public var isResponse: Bool
    public var questions: [String]
    public var answers: [Answer]

    public init?(_ data: Data) {
        let bytes = [UInt8](data)
        guard bytes.count >= 12 else { return nil }
        func u16(_ i: Int) -> UInt16? { i + 1 < bytes.count ? UInt16(bytes[i]) << 8 | UInt16(bytes[i + 1]) : nil }
        func u32(_ i: Int) -> UInt32? {
            guard let hi = u16(i), let lo = u16(i + 2) else { return nil }
            return UInt32(hi) << 16 | UInt32(lo)
        }
        id = u16(0)!
        isResponse = bytes[2] & 0x80 != 0
        let questionCount = Int(u16(4)!), answerCount = Int(u16(6)!)
        guard questionCount <= 16, answerCount <= 256 else { return nil }

        var offset = 12
        questions = []
        for _ in 0..<questionCount {
            guard let (name, next) = DNSMessage.readName(bytes, at: offset), next + 4 <= bytes.count else { return nil }
            questions.append(name)
            offset = next + 4
        }
        answers = []
        for _ in 0..<answerCount {
            guard let (name, next) = DNSMessage.readName(bytes, at: offset),
                  let type = u16(next), let ttl = u32(next + 4), let length = u16(next + 8) else { return nil }
            let start = next + 10, end = start + Int(length)
            guard end <= bytes.count else { return nil }
            var answer = Answer(name: name, type: type, ttl: ttl)
            switch type {
            case 1 where length == 4, 28 where length == 16: answer.address = IPAddress(bytes: bytes[start..<end])
            case 5: answer.target = DNSMessage.readName(bytes, at: start)?.0
            default: break
            }
            answers.append(answer)
            offset = end
        }
    }

    /// Reads a possibly-compressed name; returns it and the offset just past it in the record.
    static func readName(_ bytes: [UInt8], at start: Int) -> (String, Int)? {
        var labels: [String] = []
        var offset = start
        var resumeAt: Int?
        var jumps = 0
        while offset < bytes.count {
            let length = Int(bytes[offset])
            if length == 0 {
                return (labels.joined(separator: ".").lowercased(), resumeAt ?? offset + 1)
            }
            if length & 0xC0 == 0xC0 {
                guard offset + 1 < bytes.count, jumps < 32 else { return nil }
                if resumeAt == nil { resumeAt = offset + 2 }
                offset = (length & 0x3F) << 8 | Int(bytes[offset + 1])
                jumps += 1
                continue
            }
            guard offset + 1 + length <= bytes.count else { return nil }
            labels.append(String(decoding: bytes[(offset + 1)..<(offset + 1 + length)], as: UTF8.self))
            offset += 1 + length
        }
        return nil
    }

    /// Address → hostname pairs. The name is the one the app *asked* for, not the CDN alias
    /// at the end of the CNAME chain, since that's what users write rules about.
    public var addressMappings: [(address: IPAddress, hostname: String, ttl: UInt32)] {
        guard isResponse else { return [] }
        let asked = questions.first
        return answers.compactMap { answer in
            guard let address = answer.address else { return nil }
            return (address, asked ?? answer.name, answer.ttl)
        }
    }

    /// DNS over TCP prefixes each message with a two-byte length.
    public static func parseStream(_ data: Data) -> [DNSMessage] {
        var messages: [DNSMessage] = []
        var offset = data.startIndex
        while offset + 2 <= data.endIndex {
            let length = Int(data[offset]) << 8 | Int(data[offset + 1])
            let start = offset + 2, end = start + length
            guard length > 0, end <= data.endIndex else { break }
            if let message = DNSMessage(data[start..<end]) { messages.append(message) }
            offset = end
        }
        return messages
    }
}

/// Remembers which hostname each address was looked up as.
public struct DNSCache: Sendable {
    private struct Entry: Sendable {
        var hostname: String
        var expires: Date
    }

    private var entries: [IPAddress: Entry] = [:]
    private let capacity: Int

    public init(capacity: Int = 50_000) { self.capacity = capacity }

    public var count: Int { entries.count }

    public mutating func record(_ message: DNSMessage, now: Date = Date()) {
        for mapping in message.addressMappings {
            // Keep names well past their TTL: apps reuse connections long after the record expires.
            let lifetime = max(TimeInterval(mapping.ttl), 3600) * 4
            entries[mapping.address] = Entry(hostname: mapping.hostname, expires: now.addingTimeInterval(lifetime))
        }
        if entries.count > capacity { prune(now: now, force: true) }
    }

    public func hostname(for address: IPAddress, now: Date = Date()) -> String? {
        guard let entry = entries[address], entry.expires > now else { return nil }
        return entry.hostname
    }

    public mutating func prune(now: Date = Date(), force: Bool = false) {
        entries = entries.filter { $0.value.expires > now }
        if force, entries.count > capacity {
            let keep = entries.sorted { $0.value.expires > $1.value.expires }.prefix(capacity * 3 / 4)
            entries = Dictionary(uniqueKeysWithValues: keep.map { ($0.key, $0.value) })
        }
    }
}
