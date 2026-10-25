import ArgusKit
import CoreWLAN
import Foundation
import Network
import Observation
import os

/// Notices when the Mac joins a different network so profiles can follow it.
@MainActor @Observable
final class NetworkWatcher {
    private(set) var current: NetworkIdentity?
    @ObservationIgnored var onChange: ((NetworkIdentity) -> Void)?

    @ObservationIgnored private let monitor = NWPathMonitor()
    @ObservationIgnored private var pending: Task<Void, Never>?

    func start() {
        monitor.pathUpdateHandler = { [weak self] path in
            let kind: InterfaceKind = if path.status != .satisfied {
                .other
            } else if path.usesInterfaceType(.wifi) {
                .wifi
            } else if path.usesInterfaceType(.wiredEthernet) {
                .ethernet
            } else if path.usesInterfaceType(.cellular) {
                .cellular
            } else {
                .other
            }
            let online = path.status == .satisfied
            Task { @MainActor in self?.pathChanged(kind: kind, online: online) }
        }
        monitor.start(queue: DispatchQueue(label: "com.argus.path"))
    }

    /// Asks for Local Network access (by sending one datagram to the router) so the router's
    /// hardware address can identify this network precisely, then re-reads the network.
    func requestRouterIdentification() {
        guard let gateway = current?.gatewayAddress, let host = IPv4Address(gateway) else { return }
        let connection = NWConnection(host: .ipv4(host), port: 9, using: .udp)
        connection.start(queue: .main)
        connection.send(content: Data([0]), completion: .contentProcessed { _ in })
        Task {
            try? await Task.sleep(for: .seconds(3))
            connection.cancel()
            refresh()
        }
    }

    /// Re-reads the current network, e.g. after the user granted location access for Wi-Fi names.
    func refresh() {
        pathChanged(kind: current?.interface ?? .other, online: true, force: true)
    }

    private func pathChanged(kind: InterfaceKind, online: Bool, force: Bool = false) {
        pending?.cancel()
        guard online else { return }
        // Wait for DHCP and routes to settle before fingerprinting the network.
        pending = Task {
            try? await Task.sleep(for: .seconds(2))
            guard !Task.isCancelled else { return }
            let identity = await Task.detached { NetworkWatcher.identify(kind: kind) }.value
            NetworkWatcher.log.notice("Network: \(String(describing: identity), privacy: .public)")
            guard let identity, force || identity != current else { return }
            current = identity
            onChange?(identity)
        }
    }

    nonisolated static let log = Logger(subsystem: Bundle.main.bundleIdentifier ?? "Argus", category: "network")

    nonisolated static func identify(kind: InterfaceKind) -> NetworkIdentity? {
        let route = run("/sbin/route", ["-n", "get", "default"])
        guard let gateway = value(after: "gateway:", in: route) else { return nil }
        let interfaceName = value(after: "interface:", in: route) ?? ""
        let resolvedKind: InterfaceKind = interfaceName.hasPrefix("utun") || interfaceName.hasPrefix("ipsec") ? .vpn : kind
        var hardwareAddress: String?
        // Empty until the user grants Local Network access: macOS hides MAC addresses otherwise.
        let arp = run("/usr/sbin/arp", ["-n", gateway])
        if let range = arp.range(of: " at "), let end = arp[range.upperBound...].firstIndex(of: " ") {
            let raw = String(arp[range.upperBound..<end])
            let parts = raw.split(separator: ":")
            if parts.count == 6 {
                hardwareAddress = parts.map { $0.count == 1 ? "0" + $0 : String($0) }.joined(separator: ":").lowercased()
            }
        }
        // Wi-Fi names need Location Services permission on current macOS; nil is fine.
        let ssid = resolvedKind == .wifi ? CWWiFiClient.shared().interface()?.ssid() : nil
        return NetworkIdentity(interface: resolvedKind, ssid: ssid, gatewayAddress: gateway, gatewayHardwareAddress: hardwareAddress)
    }

    nonisolated private static func value(after key: String, in text: String) -> String? {
        for line in text.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix(key) { return trimmed.dropFirst(key.count).trimmingCharacters(in: .whitespaces) }
        }
        return nil
    }

    nonisolated private static func run(_ tool: String, _ arguments: [String]) -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: tool)
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        guard (try? process.run()) != nil else { return "" }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return String(decoding: data, as: UTF8.self)
    }
}
