import Darwin
import Foundation

public struct PeerCredentials: Sendable, Equatable {
    public var userID: UInt32
    public var pid: Int32

    public init(userID: UInt32, pid: Int32) {
        self.userID = userID
        self.pid = pid
    }
}

/// A bidirectional, ordered pipe of whole messages.
public protocol MessageChannel: AnyObject, Sendable {
    var peer: PeerCredentials { get }
    /// Starts delivery. Messages that arrived earlier are delivered first.
    func activate(onMessage: @escaping @Sendable (Data) -> Void, onClose: @escaping @Sendable () -> Void)
    func send(_ data: Data)
    func close()
}

private struct Handlers: Sendable {
    var onMessage: @Sendable (Data) -> Void
    var onClose: @Sendable () -> Void
}

// MARK: - In-process

/// Two connected endpoints in one process; the app uses this to talk to its built-in monitor.
public final class InMemoryChannel: MessageChannel, @unchecked Sendable {
    private struct State {
        var handlers: Handlers?
        var backlog: [Data] = []
        var closed = false
    }

    public let peer: PeerCredentials
    private weak var partner: InMemoryChannel?
    private let queue: DispatchQueue
    private let state = Locked(State())

    private init(peer: PeerCredentials, label: String) {
        self.peer = peer
        queue = DispatchQueue(label: "com.argus.channel.\(label)")
    }

    public static func pair() -> (client: InMemoryChannel, server: InMemoryChannel) {
        let me = PeerCredentials(userID: getuid(), pid: getpid())
        let client = InMemoryChannel(peer: me, label: "client")
        let server = InMemoryChannel(peer: me, label: "server")
        client.partner = server
        server.partner = client
        return (client, server)
    }

    public func activate(onMessage: @escaping @Sendable (Data) -> Void, onClose: @escaping @Sendable () -> Void) {
        let backlog = state.withLock { s -> [Data] in
            s.handlers = Handlers(onMessage: onMessage, onClose: onClose)
            defer { s.backlog = [] }
            return s.backlog
        }
        queue.async { backlog.forEach(onMessage) }
    }

    public func send(_ data: Data) { partner?.receive(data) }

    private func receive(_ data: Data) {
        let handler = state.withLock { s -> Handlers? in
            guard !s.closed else { return nil }
            if s.handlers == nil { s.backlog.append(data) }
            return s.handlers
        }
        guard let handler else { return }
        queue.async { handler.onMessage(data) }
    }

    public func close() {
        closeLocally()
        partner?.closeLocally()
    }

    private func closeLocally() {
        let handler = state.withLock { s -> Handlers? in
            guard !s.closed else { return nil }
            s.closed = true
            return s.handlers
        }
        guard let handler else { return }
        queue.async { handler.onClose() }
    }
}

// MARK: - Unix domain socket

public enum SocketError: Error, LocalizedError {
    case system(String, Int32)
    case pathTooLong

    public var errorDescription: String? {
        switch self {
        case .system(let call, let code): "\(call) failed: \(String(cString: strerror(code)))"
        case .pathTooLong: "Socket path is too long."
        }
    }
}

/// Length-prefixed frames over a Unix socket; used by the CLI to reach the in-app monitor.
public final class SocketChannel: MessageChannel, @unchecked Sendable {
    public let peer: PeerCredentials
    private let fd: Int32
    private let readQueue = DispatchQueue(label: "com.argus.socket.read")
    private let writeQueue = DispatchQueue(label: "com.argus.socket.write")
    private var source: DispatchSourceRead?
    private var buffer = Data()
    private let handlers = Locked<Handlers?>(nil)
    private let closed = Locked(false)

    static let maxFrame = 256 * 1024 * 1024

    init(fd: Int32) {
        self.fd = fd
        var on: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
        var credentials = xucred()
        var length = socklen_t(MemoryLayout<xucred>.size)
        let uid = getsockopt(fd, SOL_LOCAL, LOCAL_PEERCRED, &credentials, &length) == 0 ? credentials.cr_uid : UInt32.max
        var pid: pid_t = 0
        length = socklen_t(MemoryLayout<pid_t>.size)
        _ = getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &length)
        peer = PeerCredentials(userID: uid, pid: pid)
    }

    public static func connect(path: String) throws -> SocketChannel {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw SocketError.system("socket", errno) }
        var address = try socketAddress(path)
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard result == 0 else {
            let code = errno
            Darwin.close(fd)
            throw SocketError.system("connect", code)
        }
        return SocketChannel(fd: fd)
    }

    static func socketAddress(_ path: String) throws -> sockaddr_un {
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: address.sun_path) else { throw SocketError.pathTooLong }
        withUnsafeMutableBytes(of: &address.sun_path) { raw in
            raw.copyBytes(from: bytes)
            raw[bytes.count] = 0
        }
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        return address
    }

    public func activate(onMessage: @escaping @Sendable (Data) -> Void, onClose: @escaping @Sendable () -> Void) {
        let first = handlers.withLock { h -> Bool in
            defer { h = Handlers(onMessage: onMessage, onClose: onClose) }
            return h == nil
        }
        guard first else { return }
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: readQueue)
        source.setEventHandler { [weak self] in self?.readAvailable() }
        source.setCancelHandler { [fd] in Darwin.close(fd) }
        self.source = source
        source.resume()
    }

    private func readAvailable() {
        var chunk = [UInt8](repeating: 0, count: 65536)
        let count = read(fd, &chunk, chunk.count)
        guard count > 0 else {
            close()
            return
        }
        buffer.append(contentsOf: chunk[0..<count])
        while buffer.count >= 4 {
            let length = buffer.prefix(4).reduce(0) { $0 << 8 | Int($1) }
            guard length <= SocketChannel.maxFrame else { close(); return }
            guard buffer.count >= 4 + length else { break }
            let frame = buffer.subdata(in: (buffer.startIndex + 4)..<(buffer.startIndex + 4 + length))
            buffer.removeFirst(4 + length)
            handlers.withLock { $0 }?.onMessage(frame)
        }
    }

    public func send(_ data: Data) {
        var frame = Data(capacity: data.count + 4)
        let length = UInt32(data.count)
        frame.append(contentsOf: [UInt8(length >> 24), UInt8(length >> 16 & 0xFF), UInt8(length >> 8 & 0xFF), UInt8(length & 0xFF)])
        frame.append(data)
        writeQueue.async { [self, frame] in
            guard !closed.withLock({ $0 }) else { return }
            frame.withUnsafeBytes { raw in
                var offset = 0
                while offset < raw.count {
                    let written = write(fd, raw.baseAddress! + offset, raw.count - offset)
                    if written <= 0 {
                        if errno == EINTR { continue }
                        return
                    }
                    offset += written
                }
            }
        }
    }

    public func close() {
        let first = closed.withLock { c -> Bool in
            defer { c = true }
            return !c
        }
        guard first else { return }
        if let source { source.cancel() } else { Darwin.close(fd) }
        handlers.withLock { $0 }?.onClose()
    }
}

/// Accepts socket connections from processes running as the same user.
public final class SocketListener: @unchecked Sendable {
    private let fd: Int32
    private let path: String
    private let source: DispatchSourceRead

    public init(path: String, onAccept: @escaping @Sendable (SocketChannel) -> Void) throws {
        unlink(path)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw SocketError.system("socket", errno) }
        var address = try SocketChannel.socketAddress(path)
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard bound == 0, chmod(path, 0o600) == 0, listen(fd, 16) == 0 else {
            let code = errno
            Darwin.close(fd)
            throw SocketError.system("listen", code)
        }
        self.fd = fd
        self.path = path
        source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: DispatchQueue(label: "com.argus.socket.accept"))
        source.setEventHandler {
            let client = accept(fd, nil, nil)
            guard client >= 0 else { return }
            let channel = SocketChannel(fd: client)
            // Only the same user (or root) may drive the monitor.
            guard channel.peer.userID == getuid() || channel.peer.userID == 0 else {
                Darwin.close(client)
                return
            }
            onAccept(channel)
        }
        source.setCancelHandler { Darwin.close(fd) }
        source.resume()
    }

    public func close() {
        source.cancel()
        unlink(path)
    }

    deinit { close() }
}

// MARK: - XPC

@objc public protocol ArgusXPCPipe {
    func deliver(_ message: Data)
}

/// A message pipe over an NSXPCConnection; both sides export the same one-method protocol.
public final class XPCChannel: NSObject, MessageChannel, ArgusXPCPipe, @unchecked Sendable {
    private let connection: NSXPCConnection
    public let peer: PeerCredentials
    private let handlers = Locked<Handlers?>(nil)
    private let closed = Locked(false)

    public init(connection: NSXPCConnection) {
        self.connection = connection
        peer = PeerCredentials(userID: connection.effectiveUserIdentifier, pid: connection.processIdentifier)
        super.init()
        let interface = NSXPCInterface(with: ArgusXPCPipe.self)
        connection.exportedInterface = interface
        connection.remoteObjectInterface = interface
        connection.exportedObject = self
    }

    /// Connects to the network extension's Mach service.
    public static func connect(machServiceName: String, serverRequirement: String?) -> XPCChannel {
        let connection = NSXPCConnection(machServiceName: machServiceName, options: [])
        if let serverRequirement { connection.setCodeSigningRequirement(serverRequirement) }
        return XPCChannel(connection: connection)
    }

    public func activate(onMessage: @escaping @Sendable (Data) -> Void, onClose: @escaping @Sendable () -> Void) {
        // Resuming an NSXPCConnection twice is a fatal API misuse.
        let first = handlers.withLock { h -> Bool in
            defer { h = Handlers(onMessage: onMessage, onClose: onClose) }
            return h == nil
        }
        guard first else { return }
        connection.invalidationHandler = { [weak self] in self?.didClose() }
        connection.interruptionHandler = { [weak self] in self?.connection.invalidate() }
        connection.resume()
    }

    public func send(_ data: Data) {
        let proxy = connection.remoteObjectProxyWithErrorHandler { [weak self] _ in self?.connection.invalidate() }
        (proxy as? ArgusXPCPipe)?.deliver(data)
    }

    public func deliver(_ message: Data) {
        handlers.withLock { $0 }?.onMessage(message)
    }

    public func close() { connection.invalidate() }

    private func didClose() {
        let first = closed.withLock { c -> Bool in
            defer { c = true }
            return !c
        }
        guard first else { return }
        connection.exportedObject = nil // breaks the connection ↔ channel cycle
        handlers.withLock { $0 }?.onClose()
    }
}

/// Serves XPC clients on a Mach service, optionally requiring a code signature.
public final class XPCServiceListener: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
    private let listener: NSXPCListener
    private let clientRequirement: String?
    private let onAccept: @Sendable (XPCChannel) -> Void

    public init(machServiceName: String, clientRequirement: String?, onAccept: @escaping @Sendable (XPCChannel) -> Void) {
        listener = NSXPCListener(machServiceName: machServiceName)
        self.clientRequirement = clientRequirement
        self.onAccept = onAccept
        super.init()
        listener.delegate = self
    }

    public func resume() { listener.resume() }

    public func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        if let clientRequirement { connection.setCodeSigningRequirement(clientRequirement) }
        onAccept(XPCChannel(connection: connection))
        return true
    }
}
