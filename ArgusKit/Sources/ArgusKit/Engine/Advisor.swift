import Foundation

/// What earlier decisions say about a destination's domain.
public struct DomainHistory: Sendable, Equatable {
    /// This program's earlier connections to the domain that a rule or alert answer allowed.
    public var thisAppAllowed = 0
    /// …that a rule or alert answer denied.
    public var thisAppDenied = 0
    /// Other programs that connect to the domain.
    public var otherAppsUsing: [String] = []

    public init(thisAppAllowed: Int = 0, thisAppDenied: Int = 0, otherAppsUsing: [String] = []) {
        self.thisAppAllowed = thisAppAllowed
        self.thisAppDenied = thisAppDenied
        self.otherAppsUsing = otherAppsUsing
    }
}

/// Suggests an answer for a connection alert by weighing independent signals: reference
/// blocklists, who the program is, well-known services, and what the user decided before.
public enum Advisor {
    public static func advise(
        _ ctx: FlowContext,
        state: FirewallState,
        references: [(ReferenceList, CompiledBlocklist)],
        history: DomainHistory
    ) -> ConnectionAdvice? {
        var reasons: [ConnectionAdvice.Reason] = []
        var suggestedDomain: String?
        let app = ctx.process.name
        let host = ctx.hostname
        let domain = host.flatMap(DomainName.registrableDomain)

        // Reference lists.
        if let host {
            for (list, compiled) in references {
                guard let match = compiled.domains.match(host) else { continue }
                if case .suffix(let listed) = match { suggestedDomain = listed }
                switch list.kind {
                case .threat:
                    reasons.append(.init(.threatList, leansTo: .deny, strength: .strong,
                                         text: "\(list.name) lists this as malware, phishing or scam infrastructure."))
                case .tracker:
                    suggestedDomain = suggestedDomain ?? domain
                    reasons.append(.init(.trackerList, leansTo: .deny, strength: .moderate,
                                         text: "\(list.name) lists this as an advertising or tracking server."))
                }
            }
        }
        if let address = ctx.address {
            for (list, compiled) in references where list.kind == .threat && compiled.addresses.contains(address) {
                reasons.append(.init(.threatList, leansTo: .deny, strength: .strong,
                                     text: "\(list.name) lists this address as malicious."))
            }
        }

        if let host, let domain {
            // Who is on the other end.
            if isFirstParty(domain: domain, process: ctx.process) {
                suggestedDomain = suggestedDomain ?? domain
                reasons.append(.init(.firstParty, leansTo: .allow, strength: .moderate,
                                     text: "Looks like \(app)'s own server: \(app) and \(domain) come from the same company."))
            }
            if let service = knownTrackingService(host) {
                suggestedDomain = suggestedDomain ?? domain
                reasons.append(.init(.trackerService, leansTo: .deny, strength: .weak,
                                     text: "\(service) is an analytics or advertising service."))
            } else if let word = trackingWord(in: host) {
                reasons.append(.init(.trackerService, leansTo: .deny, strength: .weak,
                                     text: "“\(word)” in the name suggests analytics or telemetry."))
            }
            if appleDomains.contains(domain) {
                reasons.append(.init(.appleService, leansTo: .allow, strength: .moderate,
                                     text: "\(domain) is Apple's, used by many apps for iCloud, notifications and updates."))
            } else if let provider = sharedInfrastructure.first(where: { host == $0.suffix || host.hasSuffix("." + $0.suffix) }) {
                reasons.append(.init(.sharedInfrastructure, leansTo: .allow, strength: .weak,
                                     text: "Hosted on \(provider.name), which many apps use; who's behind it depends on the app."))
            }

            // What the user decided before.
            for rule in state.rules where rule.isEnabled && remoteDomain(rule.remote) == domain {
                if rule.action == .deny, rule.process.path != ctx.process.path {
                    let who = rule.process.path.map { ProcessIdentity.defaultName(for: $0) } ?? "every app"
                    reasons.append(.init(.yourRules, leansTo: .deny, strength: .moderate, text: "You've blocked \(domain) for \(who)."))
                    break
                }
                if rule.action == .allow, rule.process.path == ctx.process.path {
                    reasons.append(.init(.yourRules, leansTo: .allow, strength: .moderate,
                                         text: "You've already allowed \(app) to reach other \(domain) servers."))
                    break
                }
            }
            if history.thisAppDenied > 0, history.thisAppAllowed == 0 {
                reasons.append(.init(.yourHistory, leansTo: .deny, strength: .weak, text: "You've denied \(app)'s earlier connections to \(domain)."))
            } else if history.thisAppAllowed > 0, history.thisAppDenied == 0 {
                reasons.append(.init(.yourHistory, leansTo: .allow, strength: .weak, text: "You've allowed \(app)'s earlier connections to \(domain)."))
            }
            if history.otherAppsUsing.count >= 2 {
                let apps = history.otherAppsUsing
                let rest = apps.count - 2
                let names = rest == 0 ? "\(apps[0]) and \(apps[1])"
                    : "\(apps[0]), \(apps[1]) and \(rest) other app\(rest == 1 ? "" : "s")"
                reasons.append(.init(.otherApps, leansTo: .allow, strength: .weak, text: "\(names) also use \(domain)."))
            }
        }

        // The program and the direction.
        switch ctx.process.signature {
        case .unsigned:
            reasons.append(.init(.signature, leansTo: .deny, strength: .weak, text: "\(app) isn't signed, so its maker can't be verified."))
        case .invalid:
            reasons.append(.init(.signature, leansTo: .deny, strength: .moderate, text: "\(app)'s signature is broken; it may have been tampered with."))
        default:
            break
        }
        if ctx.direction == .incoming, ctx.address.map({ !$0.isLocalNetwork }) ?? false {
            reasons.append(.init(.incoming, leansTo: .deny, strength: .weak, text: "Someone on the internet is connecting in; few apps need that."))
        } else if ctx.address?.isLocalNetwork == true {
            reasons.append(.init(.localNetwork, leansTo: .allow, strength: .weak, text: "This stays on your local network."))
        }

        guard !reasons.isEmpty else { return nil }
        return combine(reasons, suggestedDomain: suggestedDomain)
    }

    static func combine(_ reasons: [ConnectionAdvice.Reason], suggestedDomain: String?) -> ConnectionAdvice {
        let sorted = reasons.sorted { $0.strength > $1.strength }
        // A known threat outweighs everything else.
        if sorted.contains(where: { $0.kind == .threatList }) {
            return ConnectionAdvice(suggestion: .deny, strength: .strong, reasons: sorted, suggestedDomain: suggestedDomain)
        }
        let score = reasons.reduce(0) { total, reason in
            switch reason.leansTo {
            case .allow: total + reason.strength.rawValue
            case .deny: total - reason.strength.rawValue
            case nil: total
            }
        }
        let suggestion: RuleAction? = score > 0 ? .allow : score < 0 ? .deny : nil
        let strength: ConnectionAdvice.Strength = abs(score) >= 4 ? .strong : abs(score) >= 2 ? .moderate : .weak
        // Only suggest whole-domain answers for the side the evidence is on.
        let domainScope = sorted.contains { $0.leansTo == suggestion && [.trackerList, .trackerService, .firstParty].contains($0.kind) }
        return ConnectionAdvice(suggestion: suggestion, strength: strength, reasons: sorted, suggestedDomain: domainScope ? suggestedDomain : nil)
    }

    // MARK: Signals

    /// The domain's brand ("google" in google.com) appears in the program's identity, e.g.
    /// Chrome (com.google.Chrome) talking to google.com.
    static func isFirstParty(domain: String, process: ProcessIdentity) -> Bool {
        guard let brand = domain.split(separator: ".").first.map(String.init), brand.count >= 3, !genericWords.contains(brand) else { return false }
        let identifiers = [process.bundleIdentifier, process.signingIdentifier].compactMap { $0?.lowercased() }
        let words = identifiers.flatMap { $0.split(whereSeparator: { !$0.isLetter && !$0.isNumber }).map(String.init) }
            + process.name.lowercased().split(whereSeparator: { !$0.isLetter && !$0.isNumber }).map(String.init)
        return words.contains(brand)
    }

    static func knownTrackingService(_ host: String) -> String? {
        trackingServices.first { host == $0.key || host.hasSuffix("." + $0.key) }?.value
    }

    static func trackingWord(in host: String) -> String? {
        for label in host.split(separator: ".").dropLast() {
            for part in label.split(separator: "-") where trackingWords.contains(String(part)) { return String(part) }
            for word in ["telemetry", "analytics", "tracking"] where label.contains(word) { return word }
        }
        return nil
    }

    static func remoteDomain(_ remote: RemoteMatch) -> String? {
        switch remote {
        case .host(let host): DomainName.registrableDomain(of: host)
        case .domain(let domain): DomainName.registrableDomain(of: domain) ?? domain
        default: nil
        }
    }

    static let genericWords: Set<String> = ["com", "net", "org", "app", "apps", "www", "api", "cdn", "mac", "macos", "desktop", "helper", "cloud", "online", "mail", "web"]

    static let trackingWords: Set<String> = [
        "telemetry", "analytics", "metrics", "tracking", "tracker", "beacon", "beacons", "pixel",
        "adserver", "adservice", "ads", "stats", "crashreport", "crashreports", "collector",
    ]

    static let trackingServices: [String: String] = [
        "doubleclick.net": "Google's DoubleClick", "google-analytics.com": "Google Analytics",
        "googletagmanager.com": "Google Tag Manager", "googlesyndication.com": "Google AdSense",
        "googleadservices.com": "Google Ads", "app-measurement.com": "Google Analytics for Firebase",
        "crashlytics.com": "Firebase Crashlytics", "sentry.io": "Sentry", "segment.io": "Segment", "segment.com": "Segment",
        "mixpanel.com": "Mixpanel", "amplitude.com": "Amplitude", "appsflyer.com": "AppsFlyer", "adjust.com": "Adjust",
        "branch.io": "Branch", "braze.com": "Braze", "newrelic.com": "New Relic", "nr-data.net": "New Relic",
        "bugsnag.com": "Bugsnag", "hotjar.com": "Hotjar", "fullstory.com": "FullStory", "scorecardresearch.com": "comScore",
        "quantserve.com": "Quantcast", "criteo.com": "Criteo", "adnxs.com": "Xandr", "taboola.com": "Taboola",
        "outbrain.com": "Outbrain", "moatads.com": "Moat", "chartbeat.com": "Chartbeat", "kochava.com": "Kochava",
        "singular.net": "Singular", "heap.io": "Heap", "posthog.com": "PostHog", "datadoghq.com": "Datadog",
        "facebook.net": "Meta Audience Network", "ads-twitter.com": "X Ads", "bat.bing.com": "Microsoft Ads",
    ]

    static let appleDomains: Set<String> = [
        "apple.com", "icloud.com", "icloud-content.com", "mzstatic.com", "aaplimg.com", "apple-cloudkit.com",
        "cdn-apple.com", "apple.news", "itunes.com", "me.com", "apple-dns.net", "apple-livephotoskit.com",
    ]

    static let sharedInfrastructure: [(suffix: String, name: String)] = [
        ("amazonaws.com", "Amazon Web Services"), ("cloudfront.net", "Amazon CloudFront"),
        ("akamaihd.net", "Akamai"), ("akamaized.net", "Akamai"), ("akamaiedge.net", "Akamai"), ("akamai.net", "Akamai"),
        ("edgekey.net", "Akamai"), ("edgesuite.net", "Akamai"), ("fastly.net", "Fastly"), ("fastlylb.net", "Fastly"),
        ("cloudflare.net", "Cloudflare"), ("azureedge.net", "Microsoft Azure"), ("azurefd.net", "Microsoft Azure"),
        ("trafficmanager.net", "Microsoft Azure"), ("windows.net", "Microsoft Azure"), ("googleapis.com", "Google Cloud"),
        ("googleusercontent.com", "Google Cloud"), ("gstatic.com", "Google"), ("1e100.net", "Google"),
        ("githubusercontent.com", "GitHub"), ("jsdelivr.net", "jsDelivr"),
    ]
}
