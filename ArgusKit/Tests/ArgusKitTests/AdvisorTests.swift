import Foundation
import Testing
@testable import ArgusKit

@Suite struct AdvisorTests {
    let chrome = ProcessIdentity(path: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", name: "Google Chrome",
                                 bundleIdentifier: "com.google.Chrome", signingIdentifier: "com.google.Chrome", signature: .developerID)
    let threats = ReferenceList(id: "t", kind: .threat, name: "Threat List", url: URL(string: "https://example.com/t")!)
    let trackers = ReferenceList(id: "k", kind: .tracker, name: "Tracker List", url: URL(string: "https://example.com/k")!)

    func advise(_ ctx: FlowContext, state: FirewallState = FirewallState(), lists: [(ReferenceList, CompiledBlocklist)] = [],
                history: DomainHistory = DomainHistory()) -> ConnectionAdvice? {
        Advisor.advise(ctx, state: state, references: lists, history: history)
    }

    @Test func recognisesAnAppsOwnServer() throws {
        let advice = try #require(advise(flow(chrome, host: "clients4.google.com")))
        #expect(advice.suggestion == .allow)
        #expect(advice.reasons.first?.kind == .firstParty)
        #expect(advice.suggestedDomain == "google.com")
        #expect(advice.headline?.contains("Google Chrome") == true)
    }

    @Test func threatListsWinOverEverything() throws {
        let list = CompiledBlocklist(domains: DomainSet(suffixes: ["google.com"]))
        let advice = try #require(advise(flow(chrome, host: "evil.google.com"), lists: [(threats, list)]))
        #expect(advice.suggestion == .deny)
        #expect(advice.strength == .strong)
        #expect(advice.reasons.first?.kind == .threatList)
    }

    @Test func trackerListsSuggestBlockingTheWholeDomain() throws {
        let list = CompiledBlocklist(domains: DomainSet(suffixes: ["tracker.io"]))
        let advice = try #require(advise(flow(host: "eu.collect.tracker.io"), lists: [(trackers, list)]))
        #expect(advice.suggestion == .deny)
        #expect(advice.strength == .moderate)
        #expect(advice.suggestedDomain == "tracker.io")
        #expect(advice.isConfident)
    }

    @Test func knownServicesAndTrackingNames() throws {
        let sentry = try #require(advise(flow(host: "o1234.ingest.sentry.io")))
        #expect(sentry.suggestion == .deny)
        #expect(sentry.reasons.first?.text.contains("Sentry") == true)
        #expect(!sentry.isConfident) // a weak hint alone shouldn't act on its own

        let telemetry = try #require(advise(flow(host: "telemetry-eu.example.com")))
        #expect(telemetry.suggestion == .deny)
        #expect(advise(flow(host: "www.example.com")) == nil) // nothing to say
    }

    @Test func appleAndSharedHosting() throws {
        #expect(advise(flow(host: "gateway.icloud.com"))?.suggestion == .allow)
        let cdn = try #require(advise(flow(host: "d111.cloudfront.net")))
        #expect(cdn.suggestion == .allow)
        #expect(cdn.strength == .weak)
    }

    @Test func pastDecisionsCount() throws {
        var state = FirewallState()
        state.rules = [Rule(action: .deny, process: .path("/Applications/Other.app/Contents/MacOS/Other"), remote: .domain("ads.example"))]
        let blocked = try #require(advise(flow(host: "cdn.ads.example"), state: state))
        #expect(blocked.suggestion == .deny)
        #expect(blocked.headline == "You've blocked ads.example for Other.")

        state.rules = [Rule(action: .allow, process: .path(unknownApp.path), remote: .host("api.example.org"))]
        #expect(advise(flow(host: "files.example.org"), state: state)?.suggestion == .allow)

        let history = DomainHistory(thisAppAllowed: 0, thisAppDenied: 0, otherAppsUsing: ["Safari", "Mail", "Notes"])
        let popular = try #require(advise(flow(host: "news.example.net"), history: history))
        #expect(popular.headline == "Safari, Mail and 1 other app also use example.net.")
    }

    @Test func signalsCombine() throws {
        // Own server (+2) and a tracking-looking name (−1): still allow, but only weakly.
        let advice = try #require(advise(flow(chrome, host: "analytics.google.com")))
        #expect(advice.suggestion == .allow)
        #expect(advice.strength == .weak)
        #expect(advice.reasons.count == 2)
    }

    @Test func unsignedAndIncoming() throws {
        let unsigned = ProcessIdentity(path: "/tmp/tool", signature: .unsigned)
        #expect(advise(flow(unsigned, host: "example.com"))?.suggestion == .deny)
        let incoming = try #require(advise(flow(host: nil, address: "203.0.113.9", direction: .incoming)))
        #expect(incoming.reasons.contains { $0.kind == .incoming })
    }

    @Test func alertsCarryAdviceAndTimeoutsCanFollowIt() async throws {
        let (core, delegate) = makeCore()
        var settings = core.state.settings
        settings.alertTimeout = 0.2
        settings.alertTimeoutAction = .deny
        settings.alertTimeoutFollowsAdvice = true
        _ = await core.handle(.updateSettings(settings), client: app, authorization: nil)
        core.installReference(CompiledBlocklist(domains: DomainSet(suffixes: ["google.com"])), id: "unused") // not a known reference id

        let released = Locked<Verdict?>(nil)
        _ = core.decide(flowID: UUID(), context: flow(chrome, host: "clients4.google.com"), resume: { v in released.withLock { $0 = v } })
        let alert = try #require(delegate.alerts.current.first)
        #expect(alert.advice?.suggestion == .allow)
        #expect(alert.advice?.isConfident == true)

        _ = core.alertShown(alert.id)
        try await Task.sleep(for: .milliseconds(700))
        #expect(released.current == Verdict(.allow, .alertTimeout)) // followed the suggestion, once
        #expect(!core.state.rules.contains { $0.remote == .host("clients4.google.com") })
    }
}
