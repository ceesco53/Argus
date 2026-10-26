import Foundation
import Security

/// Identifies programs by their code signature and checks them against stored requirements.
public enum CodeSignature {
    private static let identityCache = Locked<[String: ProcessIdentity]>([:])
    private static let requirementCache = Locked<[String: RequirementCheck]>([:])

    /// Identity of a running process. `auditToken` is preferred because PIDs can be reused.
    public static func identity(auditToken: Data?, pid: Int32, path knownPath: String? = nil) -> ProcessIdentity {
        // An audit token's pid version identifies one process instance even if the pid is reused.
        let instance = AuditToken(auditToken).map { "\($0.pid)v\($0.pidVersion)" }
            ?? "\(pid):\(ProcessLookup.startTime(pid: pid) ?? 0):\(knownPath ?? "")"
        if let cached = identityCache.withLock({ $0[instance] }) { return cached }
        let code = dynamicCode(auditToken: auditToken, pid: pid)
        let path = knownPath ?? ProcessLookup.path(pid: pid) ?? code.flatMap(mainExecutable) ?? "/unknown/pid-\(pid)"
        let identity = describe(path: path, code: code)
        identityCache.withLock { cache in
            if cache.count > 4096 { cache.removeAll(keepingCapacity: true) }
            cache[instance] = identity
        }
        return identity
    }

    /// Identity of a program on disk (static check; resources are not re-hashed).
    public static func identity(path: String) -> ProcessIdentity {
        describe(path: path, code: nil)
    }

    /// The outcome of checking a running process against a stored requirement.
    public enum RequirementCheck: Sendable, Equatable {
        case satisfied
        /// It runs code that isn't what the requirement describes: it was replaced or tampered with.
        case violated
        /// The process quit, or its program was updated or removed while it ran, so there's
        /// nothing on disk left to check it against.
        case unverifiable
    }

    /// Checks the running process against `requirement`.
    public static func check(requirement text: String, auditToken: Data?, pid: Int32) -> RequirementCheck {
        let instance = AuditToken(auditToken).map { "\($0.pid)v\($0.pidVersion)" } ?? "\(pid):\(ProcessLookup.startTime(pid: pid) ?? 0)"
        let key = "\(instance):\(text)"
        if let cached = requirementCache.withLock({ $0[key] }) { return cached }
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess, let requirement else { return .violated }
        guard let code = dynamicCode(auditToken: auditToken, pid: pid) else { return .unverifiable }
        let result: RequirementCheck = switch SecCodeCheckValidity(code, [], requirement) {
        case errSecSuccess: .satisfied
        case errSecCSReqFailed, errSecCSSignatureFailed, errSecCSSignatureInvalid, errSecCSUnsigned: .violated
        // errSecCSStaticCodeChanged and friends: an update replaced the file under the running process.
        default: .unverifiable
        }
        if result != .unverifiable {
            requirementCache.withLock { cache in
                if cache.count > 4096 { cache.removeAll(keepingCapacity: true) }
                cache[key] = result
            }
        }
        return result
    }

    /// The executable of running code; works inside the sandbox where `proc_pidpath` may not.
    static func mainExecutable(_ code: SecCode) -> String? {
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return nil }
        var info: CFDictionary?
        SecCodeCopySigningInformation(staticCode, [], &info)
        return ((info as? [String: Any])?[kSecCodeInfoMainExecutable as String] as? URL)?.path
    }

    static func dynamicCode(auditToken: Data?, pid: Int32) -> SecCode? {
        var attributes: [CFString: Any] = [:]
        if let auditToken, auditToken.count == MemoryLayout<audit_token_t>.size {
            attributes[kSecGuestAttributeAudit] = auditToken
        } else if pid > 0 {
            attributes[kSecGuestAttributePid] = pid
        } else {
            return nil
        }
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attributes as CFDictionary, [], &code) == errSecSuccess else { return nil }
        return code
    }

    static func describe(path: String, code: SecCode?) -> ProcessIdentity {
        var identity = ProcessIdentity(path: path)
        let innerBundle = ProcessIdentity.innermostAppBundle(for: path)
        identity.appBundlePath = ProcessIdentity.outermostAppBundle(for: path)
        if let innerBundle, let bundle = Bundle(path: innerBundle) {
            let info = bundle.infoDictionary ?? [:]
            identity.bundleIdentifier = bundle.bundleIdentifier
            identity.name = (info["CFBundleDisplayName"] as? String) ?? (info["CFBundleName"] as? String)
                ?? ((innerBundle as NSString).lastPathComponent as NSString).deletingPathExtension
            identity.version = info["CFBundleShortVersionString"] as? String
        }

        var staticCode: SecStaticCode?
        if let code {
            SecCodeCopyStaticCode(code, [], &staticCode)
        } else {
            SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &staticCode)
        }
        guard let staticCode else {
            // The file couldn't be opened; the kernel still vouches for Apple's own binaries.
            if let code, isPlatformBinary(code) { identity.signature = .apple }
            return identity
        }

        let validity: OSStatus = if let code {
            SecCodeCheckValidity(code, [], nil)
        } else {
            SecStaticCodeCheckValidity(staticCode, SecCSFlags(rawValue: kSecCSDoNotValidateResources), nil)
        }

        var info: CFDictionary?
        SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info)
        let dict = (info as? [String: Any]) ?? [:]
        identity.signingIdentifier = dict[kSecCodeInfoIdentifier as String] as? String
        identity.teamIdentifier = dict[kSecCodeInfoTeamIdentifier as String] as? String
        if identity.bundleIdentifier == nil, let plist = dict[kSecCodeInfoPList as String] as? [String: Any] {
            identity.bundleIdentifier = plist["CFBundleIdentifier"] as? String
        }
        let flags = (dict[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0

        func satisfies(_ text: String) -> Bool {
            var requirement: SecRequirement?
            guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess, let requirement else { return false }
            if let code { return SecCodeCheckValidity(code, [], requirement) == errSecSuccess }
            return SecStaticCodeCheckValidity(staticCode, SecCSFlags(rawValue: kSecCSDoNotValidateResources), requirement) == errSecSuccess
        }

        switch validity {
        case errSecSuccess:
            if satisfies("anchor apple") {
                identity.signature = .apple
            } else if satisfies("anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists") {
                identity.signature = .appStore
            } else if satisfies("anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists") {
                identity.signature = .developerID
            } else if satisfies("anchor apple generic") {
                identity.signature = .development
            } else if flags & 0x0002 != 0 { // kSecCodeSignatureAdhoc
                identity.signature = .adHoc
            } else {
                identity.signature = .unknown
            }
        case errSecCSUnsigned:
            identity.signature = .unsigned
        case errSecCSSignatureFailed, errSecCSSignatureInvalid, errSecCSBadResource, errSecCSResourcesInvalid,
             errSecCSResourceRulesInvalid, errSecCSBadMainExecutable, errSecCSSignatureNotVerifiable:
            identity.signature = .invalid
        default:
            // Couldn't check (e.g. the file isn't readable from here); don't accuse it of tampering.
            identity.signature = code.map(isPlatformBinary) == true ? .apple : .unknown
        }

        if identity.signature != .unsigned, identity.signature != .invalid {
            var requirement: SecRequirement?
            if SecCodeCopyDesignatedRequirement(staticCode, [], &requirement) == errSecSuccess, let requirement {
                var text: CFString?
                if SecRequirementCopyString(requirement, [], &text) == errSecSuccess { identity.designatedRequirement = text as String? }
            }
        }
        return identity
    }

    /// Whether the kernel marked this running code as part of macOS (CS_PLATFORM_BINARY).
    static func isPlatformBinary(_ code: SecCode) -> Bool {
        var info: CFDictionary?
        let staticView = unsafeBitCast(code, to: SecStaticCode.self)
        guard SecCodeCopySigningInformation(staticView, SecCSFlags(rawValue: kSecCSDynamicInformation), &info) == errSecSuccess,
              let status = (info as? [String: Any])?[kSecCodeInfoStatus as String] as? NSNumber else { return false }
        return status.uint32Value & 0x0400_0000 != 0
    }

    /// Team identifier of the running process, used to restrict who may talk to the filter.
    public static var ownTeamIdentifier: String? {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return nil }
        var info: CFDictionary?
        SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info)
        return (info as? [String: Any])?[kSecCodeInfoTeamIdentifier as String] as? String
    }
}

/// Fields of an `audit_token_t` received as raw bytes from the Network Extension framework.
public struct AuditToken: Sendable {
    public let data: Data
    private let words: [UInt32]

    public init?(_ data: Data?) {
        guard let data, data.count == 32 else { return nil }
        self.data = data
        words = data.withUnsafeBytes { raw in (0..<8).map { raw.load(fromByteOffset: $0 * 4, as: UInt32.self) } }
    }

    public var effectiveUserID: UInt32 { words[1] }
    public var pid: Int32 { Int32(bitPattern: words[5]) }
    public var pidVersion: Int32 { Int32(bitPattern: words[7]) }
}
