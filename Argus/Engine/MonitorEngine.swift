import ArgusKit
import Foundation

/// The firewall engine hosted inside the app when the network filter isn't available.
/// It sees every connection through `nettop` but can't hold or block them.
final class MonitorEngine: @unchecked Sendable {
    let core: FirewallCore
    let server: ArgusServer
    private let nettop: NettopMonitor
    private var listener: SocketListener?

    init() {
        core = FirewallCore(host: .monitor, directory: ArgusPaths.monitorDirectory())
        server = ArgusServer(core: core)
        nettop = NettopMonitor(core: core)
    }

    func start() {
        core.start()
        nettop.start()
        // Lets the `argus` command line tool reach the monitor.
        listener = try? SocketListener(path: ArgusPaths.monitorSocketPath()) { [weak self] channel in
            self?.server.accept(channel)
        }
    }

    func stop() {
        nettop.stop()
        listener?.close()
        listener = nil
        core.stop()
    }

    /// A client connected through an in-process channel.
    func makeClient() -> ArgusClient {
        let (clientEnd, serverEnd) = InMemoryChannel.pair()
        server.accept(serverEnd)
        return ArgusClient(channel: clientEnd)
    }
}
