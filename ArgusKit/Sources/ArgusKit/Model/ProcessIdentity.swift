import Foundation

/// How a program's code signature was classified when it was first seen.
public enum SignatureKind: String, Codable, Sendable, CaseIterable {
    case apple
    case appStore
    case developerID
    case development
    case adHoc
    case unsigned
    case invalid
    case unknown

    public var displayName: String {
        switch self {
        case .apple: "Apple"
        case .appStore: "Mac App Store"
        case .developerID: "Identified developer"
        case .development: "Development build"
        case .adHoc: "Ad-hoc signed"
        case .unsigned: "Unsigned"
        case .invalid: "Invalid signature"
        case .unknown: "Unknown"
        }
    }

    /// Signatures that chain to Apple and identify a publisher.
    public var isTrustedPublisher: Bool { self == .apple || self == .appStore || self == .developerID }

    public var isWarning: Bool { self == .invalid || self == .unsigned }
}

/// Everything Argus knows about the program behind a connection.
public struct ProcessIdentity: Codable, Hashable, Sendable {
    /// Executable path; rules match on this.
    public var path: String
    public var name: String
    public var bundleIdentifier: String?
    /// Outermost enclosing `.app`, used for icons and grouping helpers with their app.
    public var appBundlePath: String?
    public var signingIdentifier: String?
    public var teamIdentifier: String?
    public var signature: SignatureKind
    /// Designated requirement text captured at first sight; rules can pin to it.
    public var designatedRequirement: String?
    public var version: String?

    public init(
        path: String,
        name: String? = nil,
        bundleIdentifier: String? = nil,
        appBundlePath: String? = nil,
        signingIdentifier: String? = nil,
        teamIdentifier: String? = nil,
        signature: SignatureKind = .unknown,
        designatedRequirement: String? = nil,
        version: String? = nil
    ) {
        self.path = path
        self.name = name ?? ProcessIdentity.defaultName(for: path)
        self.bundleIdentifier = bundleIdentifier
        self.appBundlePath = appBundlePath
        self.signingIdentifier = signingIdentifier
        self.teamIdentifier = teamIdentifier
        self.signature = signature
        self.designatedRequirement = designatedRequirement
        self.version = version
    }

    public static func defaultName(for path: String) -> String {
        let last = (path as NSString).lastPathComponent
        return last.isEmpty ? path : last
    }

    /// Outermost `.app` bundle containing `path`, e.g. `/Applications/Xcode.app`.
    public static func outermostAppBundle(for path: String) -> String? {
        guard let range = path.range(of: ".app/") else { return path.hasSuffix(".app") ? path : nil }
        return String(path[..<range.lowerBound]) + ".app"
    }

    /// Innermost `.app` bundle containing `path`, so helpers get their own name.
    public static func innermostAppBundle(for path: String) -> String? {
        guard let range = path.range(of: ".app/", options: .backwards) else { return nil }
        return String(path[..<range.lowerBound]) + ".app"
    }

    public static let kernel = ProcessIdentity(path: "/kernel", name: "macOS Kernel", signature: .apple)
}
