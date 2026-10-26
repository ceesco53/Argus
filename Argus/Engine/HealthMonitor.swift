import ArgusKit
import Darwin
import Foundation
import Observation

/// Checks that DNS and the internet work, and whether a Wi-Fi sign-in page is in the way.
@MainActor @Observable
final class HealthMonitor {
    enum Status: Equatable {
        case unknown
        case checking
        case healthy
        /// A hotel/airport-style network wants the user to sign in first.
        case captivePortal
        /// DNS doesn't answer and Argus has been denying DNS traffic: probably Argus's doing.
        case argusBlockingDNS
        /// DNS doesn't answer, but not because of Argus.
        case dnsFailing
        /// Names resolve but nothing loads.
        case offline

        var isProblem: Bool { ![.unknown, .checking, .healthy].contains(self) }
    }

    private(set) var status: Status = .unknown
    private(set) var checkedAt: Date?

    /// `blockedDNSRecently` tells whether Argus denied DNS traffic in the last few minutes.
    @discardableResult
    func check(blockedDNSRecently: @escaping @MainActor () -> Bool) async -> Status {
        status = .checking
        let result: Status
        if await !HealthMonitor.resolves("captive.apple.com", timeout: 5) {
            result = blockedDNSRecently() ? .argusBlockingDNS : .dnsFailing
        } else {
            switch await HealthMonitor.probeCaptivePortal() {
            case .some(true): result = .healthy
            case .some(false): result = .captivePortal
            case .none: result = .offline
            }
        }
        status = result
        checkedAt = Date()
        return result
    }

    /// Resolves a name through the system resolver, giving up after `timeout`.
    nonisolated static func resolves(_ host: String, timeout: TimeInterval) async -> Bool {
        await withCheckedContinuation { continuation in
            let finished = Locked(false)
            @Sendable func finish(_ value: Bool) {
                let first = finished.withLock { done -> Bool in
                    defer { done = true }
                    return !done
                }
                if first { continuation.resume(returning: value) }
            }
            DispatchQueue.global(qos: .utility).async {
                var result: UnsafeMutablePointer<addrinfo>?
                let ok = getaddrinfo(host, nil, nil, &result) == 0
                if let result { freeaddrinfo(result) }
                finish(ok)
            }
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { finish(false) }
        }
    }

    /// Apple's captive-portal check: true when the internet is open, false when a sign-in page
    /// answers instead, nil when nothing answers.
    nonisolated static func probeCaptivePortal() async -> Bool? {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 6
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        let session = URLSession(configuration: configuration)
        defer { session.invalidateAndCancel() }
        guard let url = URL(string: "http://captive.apple.com/hotspot-detect.html"),
              let (data, _) = try? await session.data(from: url) else { return nil }
        return String(decoding: data, as: UTF8.self).contains("Success")
    }
}
