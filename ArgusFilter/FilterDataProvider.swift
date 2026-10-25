import ArgusKit
import Foundation
import Network
import NetworkExtension
import os

/// The socket filter. Every new TCP/UDP flow on the Mac passes through `handleNewFlow`,
/// which asks the firewall engine for a verdict. Unknown flows are paused while the Argus
/// app shows an alert and resumed with the user's answer.
final class FilterDataProvider: NEFilterDataProvider, @unchecked Sendable {
    private let log = Logger(subsystem: Bundle.main.bundleIdentifier ?? "Argus.Filter", category: "filter")

    private var core: FirewallCore!
    private var server: ArgusServer!
    private var listener: XPCServiceListener?

    /// Flows that need the provider later: paused for an alert, being captured, or carrying DNS.
    private struct TrackedFlow {
        let flow: NEFilterFlow
        let context: FlowContext
        var capturing = false
        var carriesDNS = false
    }

    private let tracked = Locked<[UUID: TrackedFlow]>([:])

    static let peekSize = 64 * 1024

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        let directory = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Argus", isDirectory: true)
        core = FirewallCore(host: .networkExtension, directory: directory)
        server = ArgusServer(core: core)
        core.start()

        if let machName = (Bundle.main.object(forInfoDictionaryKey: "NetworkExtension") as? [String: Any])?["NEMachServiceName"] as? String {
            // Only Argus binaries signed by the same team may drive the filter.
            let requirement = CodeSignature.ownTeamIdentifier.map(ArgusPaths.teamRequirement)
            let listener = XPCServiceListener(machServiceName: machName, clientRequirement: requirement) { [weak self] channel in
                self?.server.accept(channel)
            }
            listener.resume()
            self.listener = listener
            log.info("Listening on \(machName, privacy: .public)")
        }

        let everything = NENetworkRule(remoteNetworkEndpoint: nil, remotePrefix: 0, localNetworkEndpoint: nil, localPrefix: 0, protocol: .any, direction: .any)
        let settings = NEFilterSettings(rules: [NEFilterRule(networkRule: everything, action: .filterData)], defaultAction: .allow)
        nonisolated(unsafe) let completion = completionHandler
        apply(settings) { error in
            if let error { self.log.error("Applying filter settings failed: \(error.localizedDescription, privacy: .public)") }
            completion(error)
        }
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        log.info("Stopping filter (reason \(reason.rawValue))")
        // Let anything still waiting on an alert through rather than leaving it hanging.
        let waiting = tracked.withLock { flows -> [NEFilterFlow] in
            defer { flows = [:] }
            return flows.values.map(\.flow)
        }
        for flow in waiting { resumeFlow(flow, with: NEFilterNewFlowVerdict.allow()) }
        core?.stop()
        completionHandler()
    }

    // MARK: - New flows

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let socketFlow = flow as? NEFilterSocketFlow, let context = makeContext(socketFlow) else { return .allow() }
        // Loopback traffic never leaves the Mac; filtering it only adds noise.
        if context.address?.isLoopback == true { return .allow() }

        let id = flow.identifier
        let decision = core.decide(flowID: id, context: context) { [weak self] verdict in
            self?.resume(id, with: verdict)
        }
        switch decision {
        case .allow:
            return allowVerdict(for: flow, context: context)
        case .deny:
            return reported(.drop())
        case .pause:
            tracked.withLock { $0[id] = TrackedFlow(flow: flow, context: context) }
            return .pause()
        }
    }

    private func resume(_ id: UUID, with verdict: Verdict) {
        guard let entry = tracked.withLock({ $0.removeValue(forKey: id) }) else { return }
        let newVerdict = verdict.action == .allow ? allowVerdict(for: entry.flow, context: entry.context) : reported(.drop())
        resumeFlow(entry.flow, with: newVerdict)
    }

    /// Allows a flow, peeking at its data only when DNS learning or a capture needs it.
    private func allowVerdict(for flow: NEFilterFlow, context: FlowContext) -> NEFilterNewFlowVerdict {
        let id = flow.identifier
        let carriesDNS = context.remotePort == 53 && core.state.settings.learnHostnamesFromDNS
        let capturing = core.beginCaptureIfWanted(flowID: id, context: context)
        guard carriesDNS || capturing else { return reported(.allow()) }
        tracked.withLock { $0[id] = TrackedFlow(flow: flow, context: context, capturing: capturing, carriesDNS: carriesDNS) }
        return reported(.filterDataVerdict(
            withFilterInbound: true, peekInboundBytes: FilterDataProvider.peekSize,
            filterOutbound: capturing, peekOutboundBytes: capturing ? FilterDataProvider.peekSize : 0))
    }

    /// Asks for byte counts while the flow is open and a final report when it closes.
    private func reported(_ verdict: NEFilterNewFlowVerdict) -> NEFilterNewFlowVerdict {
        verdict.shouldReport = true
        verdict.statisticsReportFrequency = .medium
        return verdict
    }

    // MARK: - Data

    override func handleInboundData(from flow: NEFilterFlow, readBytesStartOffset offset: Int, readBytes: Data) -> NEFilterDataVerdict {
        handleData(flow, inbound: true, bytes: readBytes)
    }

    override func handleOutboundData(from flow: NEFilterFlow, readBytesStartOffset offset: Int, readBytes: Data) -> NEFilterDataVerdict {
        handleData(flow, inbound: false, bytes: readBytes)
    }

    private func handleData(_ flow: NEFilterFlow, inbound: Bool, bytes: Data) -> NEFilterDataVerdict {
        guard let entry = tracked.withLock({ $0[flow.identifier] }) else { return .allow() }
        if inbound, entry.carriesDNS {
            core.ingestDNS(bytes, overTCP: entry.context.proto == .tcp)
        }
        var stillCapturing = false
        if entry.capturing {
            stillCapturing = core.captures.payload(flow.identifier, inbound: inbound, data: bytes)
            if !stillCapturing { tracked.withLock { $0[flow.identifier]?.capturing = false } }
        }
        guard stillCapturing || (inbound && entry.carriesDNS) else { return .allow() }
        return NEFilterDataVerdict(passBytes: bytes.count, peekBytes: FilterDataProvider.peekSize)
    }

    override func handleInboundDataComplete(for flow: NEFilterFlow) -> NEFilterDataVerdict { .allow() }
    override func handleOutboundDataComplete(for flow: NEFilterFlow) -> NEFilterDataVerdict { .allow() }

    // MARK: - Statistics

    override func handle(_ report: NEFilterReport) {
        guard let flow = report.flow else { return }
        switch report.event {
        case .statistics:
            core.flowStatistics(flow.identifier, totalIn: UInt64(report.bytesInboundCount), totalOut: UInt64(report.bytesOutboundCount), closed: false)
        case .flowClosed:
            core.flowStatistics(flow.identifier, totalIn: UInt64(report.bytesInboundCount), totalOut: UInt64(report.bytesOutboundCount), closed: true)
            tracked.withLock { _ = $0.removeValue(forKey: flow.identifier) }
        default:
            break
        }
    }

    // MARK: - Context

    private func makeContext(_ flow: NEFilterSocketFlow) -> FlowContext? {
        let appToken = AuditToken(flow.sourceAppAuditToken)
        let processToken = AuditToken(flow.sourceProcessAuditToken)
        guard let primary = appToken ?? processToken else { return nil }

        let process = CodeSignature.identity(auditToken: primary.data, pid: primary.pid)
        var via: ProcessIdentity?
        if let processToken, processToken.pid != primary.pid {
            via = CodeSignature.identity(auditToken: processToken.data, pid: processToken.pid)
        }

        let (remoteAddress, remotePort, endpointName) = FilterDataProvider.split(flow.remoteFlowEndpoint)
        let (localAddress, localPort, _) = FilterDataProvider.split(flow.localFlowEndpoint)
        return FlowContext(
            process: process, via: via, pid: primary.pid, processStartTime: ProcessLookup.startTime(pid: primary.pid),
            userID: primary.effectiveUserID, auditToken: primary.data,
            hostname: flow.remoteHostname ?? endpointName, address: remoteAddress, remotePort: remotePort,
            localAddress: localAddress, localPort: localPort, proto: TransportProtocol(rawValue: flow.socketProtocol),
            direction: flow.direction == .inbound ? .incoming : .outgoing)
    }

    private static func split(_ endpoint: Network.NWEndpoint?) -> (ArgusKit.IPAddress?, UInt16, String?) {
        guard case .hostPort(let host, let port) = endpoint else { return (nil, 0, nil) }
        switch host {
        case .ipv4(let address): return (ArgusKit.IPAddress(bytes: address.rawValue), port.rawValue, nil)
        case .ipv6(let address): return (ArgusKit.IPAddress(bytes: address.rawValue), port.rawValue, nil)
        case .name(let name, _): return (ArgusKit.IPAddress(name), port.rawValue, ArgusKit.IPAddress(name) == nil ? name : nil)
        @unknown default: return (nil, port.rawValue, nil)
        }
    }
}
