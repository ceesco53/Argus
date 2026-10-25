import Foundation

/// Talks to a firewall engine over any `MessageChannel`.
public final class ArgusClient: @unchecked Sendable {
    private struct State {
        var nextID: UInt64 = 1
        var pending: [UInt64: CheckedContinuation<ArgusResponse, Error>] = [:]
        var closed = false
        var started = false
        var onClose: (@Sendable () -> Void)?
    }

    private let channel: MessageChannel
    private let state = Locked(State())
    private let authorizationBox = Locked<Data?>(nil)
    private let eventContinuation: AsyncStream<ArgusEvent>.Continuation

    /// Alerts, state changes and notices pushed by the engine.
    public let events: AsyncStream<ArgusEvent>

    public init(channel: MessageChannel) {
        self.channel = channel
        (events, eventContinuation) = AsyncStream.makeStream(bufferingPolicy: .bufferingNewest(500))
    }

    /// Administrator authorization attached to every request while settings are unlocked.
    public var authorization: Data? {
        get { authorizationBox.withLock { $0 } }
        set { authorizationBox.withLock { $0 = newValue } }
    }

    public var isClosed: Bool { state.withLock { $0.closed } }

    /// Called once when the connection ends. If it already has, the handler runs immediately.
    public func setCloseHandler(_ handler: @escaping @Sendable () -> Void) {
        let alreadyClosed = state.withLock { s -> Bool in
            s.onClose = handler
            return s.closed
        }
        if alreadyClosed { handler() }
    }

    /// Starts receiving. Safe to call more than once; only the first call activates the channel.
    public func start(onClose: (@Sendable () -> Void)? = nil) {
        if let onClose { setCloseHandler(onClose) }
        let first = state.withLock { s -> Bool in
            defer { s.started = true }
            return !s.started
        }
        guard first else { return }
        channel.activate(
            onMessage: { [weak self] data in self?.receive(data) },
            onClose: { [weak self] in self?.didClose() })
    }

    public func close() { channel.close() }

    /// Sends a request; returns whatever the engine answered, including `.error`.
    public func send(_ request: ArgusRequest) async throws -> ArgusResponse {
        let id: UInt64? = state.withLock { s in
            guard !s.closed else { return nil }
            defer { s.nextID += 1 }
            return s.nextID
        }
        guard let id else { throw ArgusError.disconnected }
        let data = try WireMessage.request(id: id, request, authorization: authorization).encoded()
        return try await withCheckedThrowingContinuation { continuation in
            let accepted = state.withLock { s -> Bool in
                guard !s.closed else { return false }
                s.pending[id] = continuation
                return true
            }
            guard accepted else {
                continuation.resume(throwing: ArgusError.disconnected)
                return
            }
            channel.send(data)
        }
    }

    /// Sends a request and turns `.error` responses into thrown errors.
    @discardableResult
    public func call(_ request: ArgusRequest) async throws -> ArgusResponse {
        let response = try await send(request)
        if case .error(let error) = response { throw error }
        return response
    }

    private func receive(_ data: Data) {
        guard let message = try? WireMessage.decode(data) else { return }
        switch message {
        case .response(let id, let response):
            let continuation = state.withLock { $0.pending.removeValue(forKey: id) }
            continuation?.resume(returning: response)
        case .event(let event):
            eventContinuation.yield(event)
        case .request:
            break
        }
    }

    private func didClose() {
        let (pending, onClose) = state.withLock { s -> ([CheckedContinuation<ArgusResponse, Error>], (@Sendable () -> Void)?) in
            s.closed = true
            defer {
                s.pending = [:]
                s.onClose = nil
            }
            return (Array(s.pending.values), s.onClose)
        }
        pending.forEach { $0.resume(throwing: ArgusError.disconnected) }
        eventContinuation.finish()
        onClose?()
    }
}

// MARK: - Typed helpers

public extension ArgusClient {
    func hello(_ hello: ClientHello) async throws -> ServerHello {
        guard case .hello(let value) = try await call(.hello(hello)) else { throw ArgusError.failed("Unexpected response") }
        return value
    }

    func state() async throws -> FirewallState {
        guard case .state(let value) = try await call(.getState) else { throw ArgusError.failed("Unexpected response") }
        return value
    }

    /// For requests that answer with the new state.
    func update(_ request: ArgusRequest) async throws -> FirewallState {
        guard case .state(let value) = try await call(request) else { throw ArgusError.failed("Unexpected response") }
        return value
    }

    func activity(since revision: UInt64) async throws -> ActivitySnapshot {
        guard case .activity(let value) = try await call(.getActivity(since: revision)) else { throw ArgusError.failed("Unexpected response") }
        return value
    }

    func traffic(_ query: TrafficQuery) async throws -> [TrafficBucket] {
        guard case .traffic(let value) = try await call(.getTraffic(query)) else { throw ArgusError.failed("Unexpected response") }
        return value
    }

    func pendingAlerts() async throws -> [ConnectionAlert] {
        guard case .alerts(let value) = try await call(.pendingAlerts) else { throw ArgusError.failed("Unexpected response") }
        return value
    }

    func data(_ request: ArgusRequest) async throws -> Data {
        guard case .data(let value) = try await call(request) else { throw ArgusError.failed("Unexpected response") }
        return value
    }

    func captures() async throws -> [CaptureSession] {
        guard case .captures(let value) = try await call(.listCaptures) else { throw ArgusError.failed("Unexpected response") }
        return value
    }

    func capture(_ request: ArgusRequest) async throws -> CaptureSession {
        guard case .capture(let value) = try await call(request) else { throw ArgusError.failed("Unexpected response") }
        return value
    }

    func network(_ request: ArgusRequest) async throws -> NetworkReport {
        guard case .network(let value) = try await call(request) else { throw ArgusError.failed("Unexpected response") }
        return value
    }
}
