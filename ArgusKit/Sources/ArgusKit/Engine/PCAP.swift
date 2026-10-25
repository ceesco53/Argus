import Foundation

/// Writes classic libpcap files with LINKTYPE_RAW (packets begin with the IP header).
public final class PCAPWriter {
    public static let linkTypeRaw: UInt32 = 101
    public static let snapLength: UInt32 = 262_144

    private let handle: FileHandle
    public private(set) var bytesWritten = 0
    public private(set) var packetCount = 0

    public init(url: URL) throws {
        FileManager.default.createFile(atPath: url.path, contents: nil)
        handle = try FileHandle(forWritingTo: url)
        let header = PCAPWriter.globalHeader()
        try handle.write(contentsOf: header)
        bytesWritten = header.count
    }

    public static func globalHeader() -> Data {
        var data = Data()
        data.appendLE(UInt32(0xA1B2_C3D4))
        data.appendLE(UInt16(2))
        data.appendLE(UInt16(4))
        data.appendLE(Int32(0))
        data.appendLE(UInt32(0))
        data.appendLE(snapLength)
        data.appendLE(linkTypeRaw)
        return data
    }

    public func write(_ packet: [UInt8], at date: Date = Date()) throws {
        let seconds = date.timeIntervalSince1970
        var record = Data(capacity: 16 + packet.count)
        record.appendLE(UInt32(seconds))
        record.appendLE(UInt32((seconds - seconds.rounded(.down)) * 1_000_000))
        record.appendLE(UInt32(packet.count))
        record.appendLE(UInt32(packet.count))
        record.append(contentsOf: packet)
        try handle.write(contentsOf: record)
        bytesWritten += record.count
        packetCount += 1
    }

    public func close() {
        try? handle.close()
    }
}

/// Turns socket-level payloads into plausible IP packets so standard tools can read a capture.
/// Argus filters at the socket layer, so it never sees real packets; this reconstructs the
/// TCP handshake, sequence numbers and checksums so Wireshark's "Follow Stream" works.
public struct PacketSynthesizer: Sendable {
    public let localAddress: IPAddress
    public let localPort: UInt16
    public let remoteAddress: IPAddress
    public let remotePort: UInt16
    public let proto: TransportProtocol
    public let direction: TrafficDirection

    private var localSequence: UInt32
    private var remoteSequence: UInt32
    private var isOpen = false
    private var isClosed = false

    public static let maxSegment = 8192

    public init(localAddress: IPAddress?, localPort: UInt16, remoteAddress: IPAddress?, remotePort: UInt16,
                proto: TransportProtocol, direction: TrafficDirection) {
        let remote = remoteAddress ?? .v4(0)
        self.remoteAddress = remote
        // Both ends of a packet must share an address family.
        if let local = localAddress, local.isIPv4 == remote.isIPv4 { self.localAddress = local } else { self.localAddress = remote.isIPv4 ? .v4(0) : .v6(0) }
        self.localPort = localPort == 0 ? 49152 : localPort
        self.remotePort = remotePort
        self.proto = proto
        self.direction = direction
        localSequence = UInt32.random(in: 1...UInt32.max / 2)
        remoteSequence = UInt32.random(in: 1...UInt32.max / 2)
    }

    /// The opening handshake (TCP only).
    public mutating func open() -> [[UInt8]] {
        guard proto == .tcp, !isOpen else { return [] }
        isOpen = true
        if direction == .outgoing {
            let syn = segment(fromLocal: true, flags: .syn, payload: [], ack: 0)
            localSequence &+= 1
            let synAck = segment(fromLocal: false, flags: [.syn, .ack], payload: [], ack: localSequence)
            remoteSequence &+= 1
            let ack = segment(fromLocal: true, flags: .ack, payload: [], ack: remoteSequence)
            return [syn, synAck, ack]
        } else {
            let syn = segment(fromLocal: false, flags: .syn, payload: [], ack: 0)
            remoteSequence &+= 1
            let synAck = segment(fromLocal: true, flags: [.syn, .ack], payload: [], ack: remoteSequence)
            localSequence &+= 1
            let ack = segment(fromLocal: false, flags: .ack, payload: [], ack: localSequence)
            return [syn, synAck, ack]
        }
    }

    public mutating func payload(_ data: Data, inbound: Bool) -> [[UInt8]] {
        guard !data.isEmpty else { return [] }
        var packets = open()
        let bytes = [UInt8](data)
        var offset = 0
        while offset < bytes.count {
            let chunk = Array(bytes[offset..<min(offset + PacketSynthesizer.maxSegment, bytes.count)])
            offset += chunk.count
            if proto == .tcp {
                if inbound {
                    packets.append(segment(fromLocal: false, flags: [.psh, .ack], payload: chunk, ack: localSequence))
                    remoteSequence &+= UInt32(chunk.count)
                } else {
                    packets.append(segment(fromLocal: true, flags: [.psh, .ack], payload: chunk, ack: remoteSequence))
                    localSequence &+= UInt32(chunk.count)
                }
            } else {
                packets.append(datagram(fromLocal: !inbound, payload: chunk))
            }
        }
        return packets
    }

    /// An orderly FIN exchange (TCP only).
    public mutating func close() -> [[UInt8]] {
        guard proto == .tcp, isOpen, !isClosed else { return [] }
        isClosed = true
        let fin = segment(fromLocal: true, flags: [.fin, .ack], payload: [], ack: remoteSequence)
        localSequence &+= 1
        let finAck = segment(fromLocal: false, flags: [.fin, .ack], payload: [], ack: localSequence)
        remoteSequence &+= 1
        let ack = segment(fromLocal: true, flags: .ack, payload: [], ack: remoteSequence)
        return [fin, finAck, ack]
    }

    struct TCPFlags: OptionSet {
        let rawValue: UInt8
        static let fin = TCPFlags(rawValue: 0x01)
        static let syn = TCPFlags(rawValue: 0x02)
        static let psh = TCPFlags(rawValue: 0x08)
        static let ack = TCPFlags(rawValue: 0x10)
    }

    private func segment(fromLocal: Bool, flags: TCPFlags, payload: [UInt8], ack: UInt32) -> [UInt8] {
        let (src, dst, sport, dport) = endpoints(fromLocal: fromLocal)
        var tcp = [UInt8]()
        tcp.appendBE(sport)
        tcp.appendBE(dport)
        tcp.appendBE(fromLocal ? localSequence : remoteSequence)
        tcp.appendBE(flags.contains(.ack) ? ack : 0)
        tcp.append(5 << 4)
        tcp.append(flags.rawValue)
        tcp.appendBE(UInt16(65535))
        tcp.appendBE(UInt16(0)) // checksum placeholder
        tcp.appendBE(UInt16(0))
        tcp += payload
        let sum = PacketSynthesizer.transportChecksum(src: src, dst: dst, proto: 6, segment: tcp)
        tcp[16] = UInt8(sum >> 8)
        tcp[17] = UInt8(sum & 0xFF)
        return PacketSynthesizer.ipPacket(src: src, dst: dst, proto: 6, payload: tcp)
    }

    private func datagram(fromLocal: Bool, payload: [UInt8]) -> [UInt8] {
        let (src, dst, sport, dport) = endpoints(fromLocal: fromLocal)
        let number = UInt8(truncatingIfNeeded: proto.rawValue)
        guard proto == .udp else { return PacketSynthesizer.ipPacket(src: src, dst: dst, proto: number, payload: payload) }
        var udp = [UInt8]()
        udp.appendBE(sport)
        udp.appendBE(dport)
        udp.appendBE(UInt16(truncatingIfNeeded: 8 + payload.count))
        udp.appendBE(UInt16(0))
        udp += payload
        var sum = PacketSynthesizer.transportChecksum(src: src, dst: dst, proto: 17, segment: udp)
        if sum == 0 { sum = 0xFFFF }
        udp[6] = UInt8(sum >> 8)
        udp[7] = UInt8(sum & 0xFF)
        return PacketSynthesizer.ipPacket(src: src, dst: dst, proto: 17, payload: udp)
    }

    private func endpoints(fromLocal: Bool) -> (IPAddress, IPAddress, UInt16, UInt16) {
        fromLocal ? (localAddress, remoteAddress, localPort, remotePort) : (remoteAddress, localAddress, remotePort, localPort)
    }

    static func ipPacket(src: IPAddress, dst: IPAddress, proto: UInt8, payload: [UInt8]) -> [UInt8] {
        var packet = [UInt8]()
        if src.isIPv4 {
            packet = [0x45, 0]
            packet.appendBE(UInt16(truncatingIfNeeded: 20 + payload.count))
            packet.appendBE(UInt16.random(in: 0...UInt16.max))
            packet.appendBE(UInt16(0x4000))
            packet += [64, proto, 0, 0]
            packet += src.bytes
            packet += dst.bytes
            let sum = checksum(packet)
            packet[10] = UInt8(sum >> 8)
            packet[11] = UInt8(sum & 0xFF)
        } else {
            packet = [0x60, 0, 0, 0]
            packet.appendBE(UInt16(truncatingIfNeeded: payload.count))
            packet += [proto, 64]
            packet += src.bytes
            packet += dst.bytes
        }
        return packet + payload
    }

    static func transportChecksum(src: IPAddress, dst: IPAddress, proto: UInt8, segment: [UInt8]) -> UInt16 {
        var pseudo = src.bytes + dst.bytes
        if src.isIPv4 {
            pseudo += [0, proto]
            pseudo.appendBE(UInt16(truncatingIfNeeded: segment.count))
        } else {
            pseudo.appendBE(UInt32(segment.count))
            pseudo += [0, 0, 0, proto]
        }
        return checksum(pseudo + segment)
    }

    /// RFC 1071 Internet checksum.
    static func checksum(_ bytes: [UInt8]) -> UInt16 {
        var sum: UInt32 = 0
        var i = 0
        while i + 1 < bytes.count {
            sum += UInt32(bytes[i]) << 8 | UInt32(bytes[i + 1])
            i += 2
        }
        if i < bytes.count { sum += UInt32(bytes[i]) << 8 }
        while sum >> 16 != 0 { sum = (sum & 0xFFFF) + (sum >> 16) }
        return ~UInt16(sum)
    }
}

extension Data {
    mutating func appendLE<T: FixedWidthInteger>(_ value: T) {
        Swift.withUnsafeBytes(of: value.littleEndian) { append(contentsOf: $0) }
    }
}

extension Array where Element == UInt8 {
    mutating func appendBE<T: FixedWidthInteger>(_ value: T) {
        Swift.withUnsafeBytes(of: value.bigEndian) { append(contentsOf: $0) }
    }
}
