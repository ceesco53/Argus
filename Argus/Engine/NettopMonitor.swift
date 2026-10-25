import ArgusKit
import Darwin
import Foundation

/// Feeds the in-app monitor from `nettop`, which reports every socket on the Mac, with byte
/// counts, to unprivileged users. Argus can't intervene this way, only observe.
final class NettopMonitor: @unchecked Sendable {
    private struct Connection {
        let id: UUID
        let context: FlowContext
        var totalIn: UInt64 = 0
        var totalOut: UInt64 = 0
        /// Bytes moved before Argus started watching; not counted as new traffic.
        var baselineIn: UInt64 = 0
        var baselineOut: UInt64 = 0
        var observed = false
        var closed = false
    }

    private let core: FirewallCore
    private let queue = DispatchQueue(label: "com.argus.nettop", qos: .utility)
    private let resolver = ReverseResolver()
    private var process: Process?
    private var pending = Data()
    private var shouldRun = false

    private var connections: [String: Connection] = [:]
    private var seen: Set<String> = []
    private var listeningPorts: [Int32: Set<UInt16>] = [:]
    private var currentPID: Int32 = -1
    private var currentName = ""
    private var completedSamples = 0

    init(core: FirewallCore) {
        self.core = core
    }

    func start() {
        queue.async { [self] in
            shouldRun = true
            launch()
        }
    }

    func stop() {
        queue.sync {
            shouldRun = false
            process?.terminate()
            process = nil
        }
    }

    private func launch() {
        guard shouldRun else { return }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/nettop")
        process.arguments = ["-L", "0", "-s", "1", "-n", "-x", "-J", "state,bytes_in,bytes_out"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard let self, !data.isEmpty else { return }
            self.queue.async { self.consume(data) }
        }
        process.terminationHandler = { [weak self] _ in
            pipe.fileHandleForReading.readabilityHandler = nil
            // nettop shouldn't exit on its own; if it does, start it again.
            guard let self else { return }
            self.queue.asyncAfter(deadline: .now() + 2) { [weak self] in self?.launch() }
        }
        do {
            try process.run()
            self.process = process
        } catch {
            queue.asyncAfter(deadline: .now() + 5) { [weak self] in self?.launch() }
        }
    }

    // MARK: Parsing

    private func consume(_ data: Data) {
        pending.append(data)
        while let newline = pending.firstIndex(of: UInt8(ascii: "\n")) {
            let line = String(decoding: pending[pending.startIndex..<newline], as: UTF8.self)
            pending.removeSubrange(pending.startIndex...newline)
            parse(line)
        }
    }

    private func parse(_ line: String) {
        if line.hasPrefix(",") {
            finishSample()
            return
        }
        let fields = line.split(separator: ",", omittingEmptySubsequences: false)
        guard let first = fields.first, !first.isEmpty else { return }
        guard first.hasPrefix("tcp") || first.hasPrefix("udp") else {
            // A process line: "name.pid". Names can contain dots, so the pid is after the last one.
            if let dot = first.lastIndex(of: "."), let pid = Int32(first[first.index(after: dot)...]) {
                currentPID = pid
                currentName = String(first[..<dot])
            }
            return
        }
        parseConnection(fields)
    }

    private func parseConnection(_ fields: [Substring]) {
        guard fields.count >= 4, let space = fields[0].firstIndex(of: " ") else { return }
        let family = fields[0][..<space]
        let isIPv6 = family.hasSuffix("6")
        let proto: TransportProtocol = family.hasPrefix("tcp") ? .tcp : .udp
        let ends = fields[0][fields[0].index(after: space)...].components(separatedBy: "<->")
        guard ends.count == 2 else { return }
        let local = NettopMonitor.endpoint(ends[0], ipv6: isIPv6)
        let remote = NettopMonitor.endpoint(ends[1], ipv6: isIPv6)
        let state = fields[1]

        if state == "Listen" {
            if let port = local.port { listeningPorts[currentPID, default: []].insert(port) }
            return
        }
        guard let remoteAddress = remote.address, let remotePort = remote.port, remotePort != 0,
              !remoteAddress.isLoopback, !remoteAddress.isUnspecified else { return }

        let key = "\(currentPID)|\(family)|\(ends[0])|\(ends[1])"
        seen.insert(key)
        let totalIn = UInt64(fields[2]) ?? 0
        let totalOut = UInt64(fields[3]) ?? 0

        if var connection = connections[key] {
            connection.totalIn = totalIn
            connection.totalOut = totalOut
            connections[key] = connection
            if connection.observed { report(connection, closed: false) }
            return
        }

        let pid = currentPID
        let identity = pid == 0 ? ProcessIdentity.kernel : CodeSignature.identity(auditToken: nil, pid: pid)
        let localPort = local.port ?? 0
        let incoming = proto == .tcp && listeningPorts[pid]?.contains(localPort) == true
        let context = FlowContext(
            process: identity, pid: pid, processStartTime: ProcessLookup.startTime(pid: pid),
            userID: ProcessLookup.userID(pid: pid) ?? getuid(), address: remoteAddress, remotePort: remotePort,
            localAddress: local.address, localPort: localPort, proto: proto, direction: incoming ? .incoming : .outgoing)
        var connection = Connection(id: UUID(), context: context, totalIn: totalIn, totalOut: totalOut)
        if completedSamples == 0 {
            connection.baselineIn = totalIn
            connection.baselineOut = totalOut
        }
        connections[key] = connection

        resolver.name(for: remoteAddress) { [weak self] hostname in
            guard let self else { return }
            self.queue.async { self.observe(key, hostname: hostname) }
        }
    }

    private func observe(_ key: String, hostname: String?) {
        guard var connection = connections[key], !connection.observed else { return }
        var context = connection.context
        if let hostname {
            context.hostname = hostname
            context.hostnameSource = .reverseLookup
        }
        core.observe(flowID: connection.id, context: context)
        connection.observed = true
        connections[key] = connection
        report(connection, closed: connection.closed)
        if connection.closed { connections[key] = nil }
    }

    private func report(_ connection: Connection, closed: Bool) {
        core.flowStatistics(
            connection.id,
            totalIn: connection.totalIn &- min(connection.baselineIn, connection.totalIn),
            totalOut: connection.totalOut &- min(connection.baselineOut, connection.totalOut),
            closed: closed)
    }

    private func finishSample() {
        guard !connections.isEmpty || completedSamples > 0 || !seen.isEmpty else { return }
        for (key, connection) in connections where !seen.contains(key) {
            if connection.observed {
                report(connection, closed: true)
                connections[key] = nil
            } else {
                connections[key]?.closed = true
            }
        }
        seen.removeAll(keepingCapacity: true)
        completedSamples += 1
        // Listening sockets are re-reported every sample; forget ones that went away.
        if completedSamples % 30 == 0 { listeningPorts.removeAll() }
    }

    /// "192.168.1.5:443" for IPv4, "fe80::1%en0.443" for IPv6, "*:*" when unbound.
    static func endpoint(_ text: String, ipv6: Bool) -> (address: IPAddress?, port: UInt16?) {
        guard let separator = text.lastIndex(of: ipv6 ? "." : ":") else { return (nil, nil) }
        let host = text[..<separator]
        let port = UInt16(text[text.index(after: separator)...])
        return (host == "*" ? nil : IPAddress(host), port)
    }
}

/// Reverse DNS with a cache. In monitor mode it's the only way to put names on addresses.
final class ReverseResolver: @unchecked Sendable {
    private let cache = Locked<[IPAddress: String?]>([:])
    private let waiting = Locked<[IPAddress: [@Sendable (String?) -> Void]]>([:])
    private let lookups = DispatchQueue(label: "com.argus.reverse-dns", qos: .utility, attributes: .concurrent)
    private let limit = DispatchSemaphore(value: 8)

    func name(for address: IPAddress, completion: @escaping @Sendable (String?) -> Void) {
        if let cached = cache.withLock({ $0[address] }) {
            completion(cached)
            return
        }
        let first = waiting.withLock { waiters -> Bool in
            defer { waiters[address, default: []].append(completion) }
            return waiters[address] == nil
        }
        guard first else { return }
        lookups.async { [self] in
            limit.wait()
            let name = ReverseResolver.lookup(address)
            limit.signal()
            cache.withLock { cache in
                if cache.count > 20_000 { cache.removeAll(keepingCapacity: true) }
                cache[address] = .some(name)
            }
            let callbacks = waiting.withLock { $0.removeValue(forKey: address) ?? [] }
            callbacks.forEach { $0(name) }
        }
    }

    private static func lookup(_ address: IPAddress) -> String? {
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let result: Int32
        switch address {
        case .v4:
            var sin = sockaddr_in()
            sin.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            sin.sin_family = sa_family_t(AF_INET)
            withUnsafeMutableBytes(of: &sin.sin_addr) { $0.copyBytes(from: address.bytes) }
            result = withUnsafePointer(to: &sin) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    getnameinfo($0, socklen_t(MemoryLayout<sockaddr_in>.size), &host, socklen_t(host.count), nil, 0, NI_NAMEREQD)
                }
            }
        case .v6:
            var sin6 = sockaddr_in6()
            sin6.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            sin6.sin6_family = sa_family_t(AF_INET6)
            withUnsafeMutableBytes(of: &sin6.sin6_addr) { $0.copyBytes(from: address.bytes) }
            result = withUnsafePointer(to: &sin6) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    getnameinfo($0, socklen_t(MemoryLayout<sockaddr_in6>.size), &host, socklen_t(host.count), nil, 0, NI_NAMEREQD)
                }
            }
        }
        guard result == 0 else { return nil }
        let name = host.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }.lowercased()
        return name.isEmpty || IPAddress(name) != nil ? nil : name
    }
}
