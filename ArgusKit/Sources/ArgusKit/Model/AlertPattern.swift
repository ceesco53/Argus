import Foundation

/// What an alert has in common with the app's other waiting alerts and the rules already made for
/// it, when that's wider than one server on one port.
///
/// A game reaches relay after relay, each at a new address and often on a new port. With no names
/// to tell them apart there's nothing to decide between one and the next, so answering them one at
/// a time takes hundreds of alerts and leaves as many rules. The pattern is the answer that takes
/// them all in: the network the addresses share, or any server once they're spread over several
/// networks, on the stretch of ports the app keeps to.
public struct AlertPattern: Hashable, Sendable {
    public enum Servers: Hashable, Sendable {
        /// The network around the alert's address that the app's other servers are in too.
        case network(IPNetwork)
        case any
    }

    /// Wider than the alert's own server; nil leaves the server as it is.
    public var servers: Servers?
    /// The stretch of neighbouring ports the app uses; nil leaves the alert's one port.
    public var ports: PortRange?

    public init(servers: Servers? = nil, ports: PortRange? = nil) {
        self.servers = servers
        self.ports = ports
    }

    /// Ports no further apart than this are one stretch.
    static let portGap = 100
    /// How many different ports make a stretch: two could be a service and its alternative.
    static let portsInAStretch = 3
    /// Spread wider than this, the ports aren't neighbours: the app picks them at random.
    static let widestStretch = 1000
    /// How many other networks an app's nameless servers must be in before any server is the
    /// pattern, rather than the network around this one.
    static let networksForAnyServer = 3

    /// The stretch of ports `port` belongs to given the others seen, in whole hundreds
    /// (27000–27099, so the next relay's port is likely in it): at least three different ports,
    /// each within `portGap` of the next.
    static func stretch(around port: UInt16, in spans: [ClosedRange<UInt16>]) -> PortRange? {
        // Below 1024 every port is a service of its own, and neighbours mean nothing.
        guard port >= 1024 else { return nil }
        var members = [port...port]
        var rest = spans.filter { $0.lowerBound >= 1024 }
        var low = Int(port), high = Int(port)
        while let index = rest.firstIndex(where: { Int($0.lowerBound) <= high + portGap && Int($0.upperBound) >= low - portGap }) {
            let span = rest.remove(at: index)
            members.append(span)
            low = min(low, Int(span.lowerBound))
            high = max(high, Int(span.upperBound))
        }
        let different = IPRangeSet.merge(members).reduce(0) { $0 + Int($1.upperBound - $1.lowerBound) + 1 }
        guard different >= portsInAStretch, high - low <= widestStretch else { return nil }
        return PortRange(UInt16(max(1024, low / 100 * 100)), UInt16(min(Int(UInt16.max), high / 100 * 100 + 99)))
    }

    /// The network to offer around an address: x.x.x.* or, wider, x.x.*.* (a /64 or /48 for IPv6).
    static func network(around address: IPAddress, wide: Bool) -> IPNetwork {
        IPNetwork(address: address, prefixLength: address.isIPv4 ? (wide ? 16 : 24) : (wide ? 48 : 64))
    }
}

/// A server an app was answered for, or is waiting to be, and the ports it was on.
private struct Sighting {
    enum Place: Hashable {
        case address(IPAddress), network(IPNetwork), name(String), anywhere

        init?(_ remote: RemoteMatch) {
            switch remote {
            case .any: self = .anywhere
            case .localNetwork: return nil
            case .host(let host): self = IPAddress(host).map(Place.address) ?? .name(host)
            case .domain(let domain): self = .name(domain)
            case .address(let text):
                guard let network = IPNetwork(text) else { return nil }
                self = network.isSingleAddress ? .address(network.address) : .network(network)
            }
        }
    }

    var place: Place
    /// nil: any port.
    var ports: ClosedRange<UInt16>?
}

extension ConnectionAlert {
    /// The address of a server on the internet that came without a name.
    private var namelessAddress: IPAddress? {
        guard hostname == nil, let ip = address.flatMap({ IPAddress($0) }), !ip.isLocalNetwork else { return nil }
        return ip
    }

    /// The networks around this alert's address to offer in place of the one address, narrowest
    /// first. None for a server with a name, which its domain widens instead, or on the local network.
    public var networks: [IPNetwork] {
        guard let ip = namelessAddress else { return [] }
        return [AlertPattern.network(around: ip, wide: false), AlertPattern.network(around: ip, wide: true)]
    }

    /// What this alert has in common with the app's others, when that's wider than its one
    /// server and port; nil when it stands alone.
    /// - Parameters:
    ///   - rules: the user's rules. The app's enabled ones are the servers it was answered for.
    ///   - waiting: every waiting alert. The app's others are servers about to be answered.
    public func pattern(rules: [Rule], waiting: [ConnectionAlert]) -> AlertPattern? {
        guard direction == .outgoing else { return nil }
        let own = rules.filter { rule in
            rule.isEnabled && rule.process == .path(process.path) && rule.direction != .incoming
                && (rule.userID == nil || rule.userID == userID)
        }
        var sightings: [Sighting] = []
        for rule in own {
            guard let place = Sighting.Place(rule.remote) else { continue }
            switch rule.ports {
            case .any: if place != .anywhere { sightings.append(Sighting(place: place, ports: nil)) }
            case .ranges(let ranges): sightings += ranges.map { Sighting(place: place, ports: $0.lower...$0.upper) }
            }
        }
        for other in waiting where other.id != id && other.process.path == process.path && other.direction == .outgoing {
            guard let place = other.hostname.map(Sighting.Place.name)
                ?? other.address.flatMap({ IPAddress($0) }).map(Sighting.Place.address) else { continue }
            sightings.append(Sighting(place: place, ports: other.port...other.port))
        }

        let stretch = AlertPattern.stretch(around: port, in: sightings.compactMap(\.ports))
        var servers: AlertPattern.Servers?
        // Servers with names are told apart by them, and a domain widens those. It's the nameless
        // ones, on the ports this one is on, that there's nothing to choose between.
        if let ip = namelessAddress {
            let ports = stretch.map { $0.lower...$0.upper } ?? port...port
            let near = AlertPattern.network(around: ip, wide: false), wide = AlertPattern.network(around: ip, wide: true)
            var neighbours = Set<IPAddress>(), elsewhere = Set<IPNetwork>()
            var extending: IPNetwork?, anywhere = false
            for sighting in sightings where sighting.ports.map(ports.overlaps) ?? true {
                switch sighting.place {
                case .address(let other) where other == ip || other.isLocalNetwork: break
                case .address(let other) where wide.contains(other): neighbours.insert(other)
                case .address(let other): elsewhere.insert(AlertPattern.network(around: other, wide: true))
                // A network already answered for on the neighbouring ports: this is more of it.
                case .network(let network) where network.contains(ip):
                    if extending.map({ network.prefixLength < $0.prefixLength }) ?? true { extending = network }
                case .network(let network): elsewhere.insert(network)
                case .anywhere: anywhere = true
                case .name: break
                }
            }
            let nearby = neighbours.count(where: near.contains)
            // Any server is a lot to start on, so only for an app that was never denied anything.
            if !own.contains(where: { $0.action == .deny }), anywhere || elsewhere.count >= AlertPattern.networksForAnyServer {
                servers = .any
            } else if let extending {
                servers = .network(extending)
            } else if neighbours.count >= 2, neighbours.count > nearby {
                servers = .network(wide)
            } else if nearby >= 1 {
                servers = .network(near)
            }
        }
        guard servers != nil || stretch != nil else { return nil }
        return AlertPattern(servers: servers, ports: stretch)
    }

    /// The connection this alert is about, as rules see it.
    var flow: FlowContext {
        FlowContext(process: process, via: via, pid: pid, userID: userID, hostname: hostname,
                    address: address.flatMap { IPAddress($0) }, remotePort: port, localPort: port, proto: proto, direction: direction)
    }

    /// What an answer takes in beyond this alert: the other waiting alerts its rule answers too,
    /// and how many earlier answers that rule replaces (`RuleAnalysis.answersReplaced`).
    public func reach(of decision: AlertDecision, state: FirewallState, waiting: [ConnectionAlert]) -> AlertReach {
        guard decision.duration != .once else { return AlertReach() }
        let profile = state.settings.activeProfileID
        let rule = decision.rule(process: process, hostname: hostname, address: address.flatMap { IPAddress($0) }, port: port,
                                 direction: direction, userID: userID, activeProfile: profile)
        let compiled = CompiledRuleSet(rules: [rule], activeProfile: profile, blocklists: [])
        let alerts = Set(waiting.filter { $0.id != id && compiled.evaluate($0.flow) != nil }.map(\.id))
        // A rule that ends leaves the ones it covers in place for when it's gone.
        guard decision.duration == .forever else { return AlertReach(alerts: alerts) }
        let listed = state.ruleGroups.filter(\.isEnabled).flatMap(\.rules)
        return AlertReach(alerts: alerts, rules: RuleAnalysis.answersReplaced(by: rule, in: state.rules, alongside: listed).count)
    }
}

/// What an answer takes in beyond its own alert.
public struct AlertReach: Hashable, Sendable {
    /// Other waiting alerts the answer's rule answers too.
    public var alerts: Set<UUID>
    /// Earlier answers the rule takes the place of.
    public var rules: Int

    public init(alerts: Set<UUID> = [], rules: Int = 0) {
        self.alerts = alerts
        self.rules = rules
    }

    public var isEmpty: Bool { alerts.isEmpty && rules == 0 }
}
