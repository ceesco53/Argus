import Foundation

/// Serves a `FirewallCore` to any number of clients and routes alerts to them.
public final class ArgusServer: FirewallCoreDelegate, @unchecked Sendable {
    private final class Session: @unchecked Sendable {
        let channel: MessageChannel
        let hello = Locked<ClientHello?>(nil)

        init(channel: MessageChannel) { self.channel = channel }

        var wantsAlerts: Bool { hello.withLock { $0?.wantsAlerts ?? false } }
        var role: ClientRole { hello.withLock { $0?.role ?? .commandLine } }
    }

    public let core: FirewallCore
    private let sessions = Locked<[ObjectIdentifier: Session]>([:])

    public init(core: FirewallCore) {
        self.core = core
        core.delegate = self
    }

    public func accept(_ channel: MessageChannel) {
        let session = Session(channel: channel)
        let key = ObjectIdentifier(session)
        sessions.withLock { $0[key] = session }
        channel.activate(
            onMessage: { [weak self, weak session] data in
                guard let self, let session else { return }
                self.receive(data, from: session)
            },
            onClose: { [weak self] in
                _ = self?.sessions.withLock { $0.removeValue(forKey: key) }
            })
    }

    public var interactiveClientCount: Int {
        sessions.withLock { $0.values.filter(\.wantsAlerts).count }
    }

    private func receive(_ data: Data, from session: Session) {
        guard case .request(let id, let request, let authorization) = try? WireMessage.decode(data) else {
            // A newer client asking for something this engine doesn't know: answer instead of
            // leaving it waiting forever.
            if let id = ArgusServer.requestID(in: data),
               let reply = try? WireMessage.response(id: id, .error(.unsupported("The Argus engine is older than the app. Restart Argus to update it."))).encoded() {
                session.channel.send(reply)
            }
            return
        }
        if case .hello(let hello) = request { session.hello.withLock { $0 = hello } }
        let client = ClientContext(userID: session.channel.peer.userID, pid: session.channel.peer.pid, role: session.role)
        Task {
            let response = await core.handle(request, client: client, authorization: authorization)
            if let reply = try? WireMessage.response(id: id, response).encoded() {
                session.channel.send(reply)
            }
        }
    }

    /// The id of a request that couldn't be decoded, read straight from the JSON.
    static func requestID(in data: Data) -> UInt64? {
        guard let message = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let request = message["request"] as? [String: Any] else { return nil }
        return (request["id"] as? NSNumber)?.uint64Value
    }

    // MARK: FirewallCoreDelegate

    public func firewallCore(_ core: FirewallCore, present alert: ConnectionAlert) -> Bool {
        let interactive = sessions.withLock { $0.values.filter(\.wantsAlerts) }
        guard !interactive.isEmpty else { return false }
        // Prefer the user who owns the process; system daemons go to everyone.
        let owners = interactive.filter { $0.channel.peer.userID == alert.userID }
        let targets = owners.isEmpty ? interactive : owners
        guard let data = try? WireMessage.event(.alert(alert)).encoded() else { return false }
        targets.forEach { $0.channel.send(data) }
        return true
    }

    public func firewallCore(_ core: FirewallCore, broadcast event: ArgusEvent) {
        guard let data = try? WireMessage.event(event).encoded() else { return }
        let all = sessions.withLock { Array($0.values) }
        all.forEach { $0.channel.send(data) }
    }
}
