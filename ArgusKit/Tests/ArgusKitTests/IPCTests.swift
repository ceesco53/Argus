import Foundation
import Testing
@testable import ArgusKit

@Suite struct IPCTests {
    func exercise(_ client: ArgusClient, delegateCore core: FirewallCore) async throws {
        let hello = try await client.hello(ClientHello(role: .app, wantsAlerts: true))
        #expect(hello.host == core.host)

        let state = try await client.update(.saveRule(Rule(action: .deny, remote: .host("blocked.example"))))
        #expect(state.rules.contains { $0.remote == .host("blocked.example") })

        // An alert raised by the engine reaches the client, and the answer releases the connection.
        let released = Locked<Verdict?>(nil)
        var events = client.events.makeAsyncIterator()
        _ = core.decide(flowID: UUID(), context: flow(), resume: { verdict in released.withLock { $0 = verdict } })
        var alert: ConnectionAlert?
        while alert == nil, let event = await events.next() {
            if case .alert(let a) = event { alert = a }
        }
        let received = try #require(alert)
        #expect(received.hostname == "api.example.com")
        try await client.call(.resolveAlert(received.id, AlertDecision(action: .deny, duration: .once)))
        #expect(released.current?.action == .deny)

        // Errors come back as thrown ArgusErrors.
        await #expect(throws: ArgusError.self) { try await client.call(.resolveAlert(UUID(), AlertDecision(action: .allow))) }
    }

    @Test func inMemoryRoundTrip() async throws {
        let (core, _) = makeCore()
        let server = ArgusServer(core: core)
        let (clientEnd, serverEnd) = InMemoryChannel.pair()
        server.accept(serverEnd)
        let client = ArgusClient(channel: clientEnd)
        client.start()
        try await exercise(client, delegateCore: core)
        client.close()
    }

    @Test func socketRoundTrip() async throws {
        let (core, _) = makeCore(host: .monitor)
        let server = ArgusServer(core: core)
        let path = "/tmp/argus-test-\(getpid())-\(Int.random(in: 0..<100_000)).sock"
        let listener = try SocketListener(path: path) { channel in server.accept(channel) }
        defer { listener.close() }

        let channel = try SocketChannel.connect(path: path)
        #expect(channel.peer.userID == getuid())
        let client = ArgusClient(channel: channel)
        client.start()
        try await exercise(client, delegateCore: core)

        // Large payloads survive framing.
        let big = String(repeating: "x", count: 300_000)
        let state = try await client.update(.saveRule(Rule(action: .allow, remote: .any, notes: big)))
        #expect(state.rules.last?.notes.count == 300_000)
        client.close()
    }

    @Test func disconnectFailsPendingRequests() async {
        let (clientEnd, serverEnd) = InMemoryChannel.pair()
        serverEnd.activate(onMessage: { _ in }, onClose: {}) // never answers
        let client = ArgusClient(channel: clientEnd)
        client.start()
        let request = Task { try await client.send(.getState) }
        try? await Task.sleep(for: .milliseconds(50))
        serverEnd.close()
        await #expect(throws: ArgusError.disconnected) { _ = try await request.value }
    }
}

@Suite struct ClientLifecycleTests {
    @Test func startingTwiceIsHarmlessAndCloseHandlersFire() async throws {
        let (core, _) = makeCore()
        let server = ArgusServer(core: core)
        let (clientEnd, serverEnd) = InMemoryChannel.pair()
        server.accept(serverEnd)
        let client = ArgusClient(channel: clientEnd)
        client.start()
        _ = try await client.hello(ClientHello(role: .app, wantsAlerts: true))
        let closed = Locked(0)
        client.start { closed.withLock { $0 += 1 } } // adopting an already-started client
        _ = try await client.state()
        serverEnd.close()
        try await Task.sleep(for: .milliseconds(50))
        #expect(closed.current == 1)
        client.setCloseHandler { closed.withLock { $0 += 1 } } // set after closing: runs at once
        #expect(closed.current == 2)
    }
}

@Suite struct VersionSkewTests {
    @Test func unknownRequestsGetAnAnswer() async throws {
        let (core, _) = makeCore()
        let server = ArgusServer(core: core)
        let (clientEnd, serverEnd) = InMemoryChannel.pair()
        server.accept(serverEnd)
        let reply = Locked<Data?>(nil)
        clientEnd.activate(onMessage: { data in reply.withLock { $0 = data } }, onClose: {})
        // A request from a future version: a case this engine doesn't have.
        clientEnd.send(Data(#"{"request":{"id":42,"_1":{"teleport":{}},"authorization":null}}"#.utf8))
        try await Task.sleep(for: .milliseconds(100))
        let data = try #require(reply.current)
        guard case .response(42, .error(.unsupported)) = try WireMessage.decode(data) else {
            Issue.record("expected an unsupported error for request 42")
            return
        }
    }
}
