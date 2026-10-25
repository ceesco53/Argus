import Foundation

/// Records the payload of selected connections into PCAP files.
public final class CaptureManager: @unchecked Sendable {
    private struct Active {
        var session: CaptureSession
        var request: CaptureRequest
        var writer: PCAPWriter
        var flows: [UUID: PacketSynthesizer] = [:]
    }

    private struct State {
        var active: [UUID: Active] = [:]
        var finished: [UUID: CaptureSession] = [:]
    }

    private let directory: URL
    private let state = Locked(State())

    public init(directory: URL) {
        self.directory = directory
        if let data = try? Data(contentsOf: indexURL),
           let sessions = try? JSONDecoder().decode([CaptureSession].self, from: data) {
            state.withLock { s in
                for var session in sessions {
                    if session.endedAt == nil { session.endedAt = Date() } // interrupted by a restart
                    s.finished[session.id] = session
                }
            }
        }
    }

    private var indexURL: URL { directory.appendingPathComponent("captures.json") }
    private func fileURL(_ id: UUID) -> URL { directory.appendingPathComponent("\(id.uuidString).pcap") }

    public var isCapturing: Bool { state.withLock { !$0.active.isEmpty } }

    public func start(_ request: CaptureRequest, processName: String?) throws -> CaptureSession {
        let id = UUID()
        let writer = try PCAPWriter(url: fileURL(id))
        let session = CaptureSession(
            id: id, processPath: request.processPath, processName: processName, remoteFilter: request.remoteFilter,
            startedAt: Date(), endedAt: nil, packetCount: 0, flowCount: 0, fileSize: writer.bytesWritten, maxBytes: request.maxBytes)
        state.withLock { $0.active[id] = Active(session: session, request: request, writer: writer) }
        return session
    }

    @discardableResult
    public func stop(_ id: UUID) -> CaptureSession? {
        let session: CaptureSession? = state.withLock { s in
            guard var active = s.active.removeValue(forKey: id) else { return s.finished[id] }
            for key in Array(active.flows.keys) {
                for packet in active.flows[key]!.close() { try? active.writer.write(packet) }
            }
            active.writer.close()
            active.session.endedAt = Date()
            active.session.packetCount = active.writer.packetCount
            active.session.fileSize = active.writer.bytesWritten
            s.finished[id] = active.session
            return active.session
        }
        saveIndex()
        return session
    }

    public func list() -> [CaptureSession] {
        state.withLock { s in
            let active = s.active.values.map { a -> CaptureSession in
                var session = a.session
                session.packetCount = a.writer.packetCount
                session.fileSize = a.writer.bytesWritten
                return session
            }
            return (active + Array(s.finished.values)).sorted { $0.startedAt > $1.startedAt }
        }
    }

    public func data(for id: UUID) throws -> Data {
        guard state.withLock({ $0.finished[id] != nil || $0.active[id] != nil }) else { throw ArgusError.notFound("Capture") }
        return try Data(contentsOf: fileURL(id))
    }

    public func delete(_ id: UUID) {
        stop(id)
        state.withLock { _ = $0.finished.removeValue(forKey: id) }
        try? FileManager.default.removeItem(at: fileURL(id))
        saveIndex()
    }

    // MARK: Flow hooks

    public func wantsFlow(_ ctx: FlowContext) -> Bool {
        state.withLock { s in s.active.values.contains { CaptureManager.matches($0.request, ctx) } }
    }

    public func beginFlow(_ id: UUID, context ctx: FlowContext) {
        state.withLock { s in
            for key in Array(s.active.keys) where CaptureManager.matches(s.active[key]!.request, ctx) {
                s.active[key]!.flows[id] = PacketSynthesizer(
                    localAddress: ctx.localAddress, localPort: ctx.localPort, remoteAddress: ctx.address,
                    remotePort: ctx.remotePort, proto: ctx.proto, direction: ctx.direction)
                s.active[key]!.session.flowCount += 1
            }
        }
    }

    /// Returns false once no capture wants this flow any more, so the filter can stop peeking.
    @discardableResult
    public func payload(_ id: UUID, inbound: Bool, data: Data) -> Bool {
        state.withLock { s in
            var wanted = false
            for key in Array(s.active.keys) where s.active[key]!.flows[id] != nil {
                wanted = true
                let packets = s.active[key]!.flows[id]!.payload(data, inbound: inbound)
                for packet in packets { try? s.active[key]!.writer.write(packet) }
            }
            return wanted
        }
    }

    public func endFlow(_ id: UUID) {
        state.withLock { s in
            for key in Array(s.active.keys) {
                guard var synthesizer = s.active[key]!.flows.removeValue(forKey: id) else { continue }
                for packet in synthesizer.close() { try? s.active[key]!.writer.write(packet) }
            }
        }
    }

    /// Stops captures that hit their size or time limit; returns them.
    public func enforceLimits(now: Date = Date()) -> [CaptureSession] {
        let expired: [UUID] = state.withLock { s in
            s.active.values.filter { a in
                a.writer.bytesWritten >= a.request.maxBytes
                    || a.request.duration.map { now.timeIntervalSince(a.session.startedAt) >= $0 } ?? false
            }.map(\.session.id)
        }
        return expired.compactMap { stop($0) }
    }

    static func matches(_ request: CaptureRequest, _ ctx: FlowContext) -> Bool {
        if let path = request.processPath, path != ctx.process.path { return false }
        if let filter = request.remoteFilter?.lowercased(), !filter.isEmpty {
            let haystack = [ctx.hostname, ctx.address?.description].compactMap { $0 }
            return haystack.contains { $0.contains(filter) }
        }
        return true
    }

    private func saveIndex() {
        let sessions = state.withLock { Array($0.finished.values) }
        if let data = try? JSONEncoder().encode(sessions) { try? data.write(to: indexURL, options: .atomic) }
    }
}
