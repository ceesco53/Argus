import Foundation
import Security

/// Administrator authorization for changing locked settings.
///
/// The client obtains the right interactively and sends the externalized form with each
/// request; the engine re-checks it without user interaction, so a client can't simply
/// claim to be authorized.
public enum AdminAuthorization {
    /// Requires an administrator's credentials by default on macOS.
    public static let rightName = "system.preferences"

    public enum Failure: LocalizedError {
        case cancelled
        case denied(OSStatus)

        public var errorDescription: String? {
            switch self {
            case .cancelled: "Authentication was cancelled."
            case .denied(let status): "Authentication failed (\(status))."
            }
        }
    }

    /// Prompts for an administrator and returns an authorization to attach to requests.
    public static func obtain(prompt: String = "Argus needs an administrator to change locked settings.") throws -> Data {
        var reference: AuthorizationRef?
        var status = AuthorizationCreate(nil, nil, [], &reference)
        guard status == errAuthorizationSuccess, let reference else { throw Failure.denied(status) }
        status = copyRights(reference, flags: [.interactionAllowed, .extendRights, .preAuthorize], prompt: prompt)
        guard status == errAuthorizationSuccess else {
            AuthorizationFree(reference, [])
            throw status == errAuthorizationCanceled ? Failure.cancelled : Failure.denied(status)
        }
        var external = AuthorizationExternalForm()
        status = AuthorizationMakeExternalForm(reference, &external)
        guard status == errAuthorizationSuccess else { throw Failure.denied(status) }
        // The reference must stay alive for the external form to remain valid.
        retained.withLock { $0.append(reference) }
        return withUnsafeBytes(of: &external) { Data($0) }
    }

    private static let retained = Locked<[AuthorizationRef]>([])

    /// Checks an authorization received from a client without prompting.
    public static func verify(_ data: Data?) -> Bool {
        guard let data, data.count == MemoryLayout<AuthorizationExternalForm>.size else { return false }
        var external = AuthorizationExternalForm()
        withUnsafeMutableBytes(of: &external) { $0.copyBytes(from: data) }
        var reference: AuthorizationRef?
        guard AuthorizationCreateFromExternalForm(&external, &reference) == errAuthorizationSuccess, let reference else { return false }
        defer { AuthorizationFree(reference, []) }
        return copyRights(reference, flags: [.extendRights], prompt: nil) == errAuthorizationSuccess
    }

    private static func copyRights(_ reference: AuthorizationRef, flags: AuthorizationFlags, prompt: String?) -> OSStatus {
        rightName.withCString { name in
            var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
            return withUnsafeMutablePointer(to: &item) { itemPointer in
                var rights = AuthorizationRights(count: 1, items: itemPointer)
                guard let prompt else { return AuthorizationCopyRights(reference, &rights, nil, flags, nil) }
                return kAuthorizationEnvironmentPrompt.withCString { promptKey in
                    prompt.withCString { promptValue in
                        var promptItem = AuthorizationItem(name: promptKey, valueLength: strlen(promptValue),
                                                           value: UnsafeMutableRawPointer(mutating: promptValue), flags: 0)
                        return withUnsafeMutablePointer(to: &promptItem) { promptPointer in
                            var environment = AuthorizationEnvironment(count: 1, items: promptPointer)
                            return AuthorizationCopyRights(reference, &rights, &environment, flags, nil)
                        }
                    }
                }
            }
        }
    }
}
