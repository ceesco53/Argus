import ArgusKit
import Foundation
import NetworkExtension
import Observation
import Security
import SystemExtensions

/// Installs, enables and removes the Argus network filter (a Network Extension system extension).
@MainActor @Observable
final class FilterManager: NSObject {
    enum Status: Equatable {
        case checking
        /// This build isn't signed with Apple's Network Extension entitlement.
        case unavailable
        case notInstalled
        case installing
        /// macOS is waiting for the user to allow the extension in System Settings.
        case awaitingApproval
        /// Installed, but the filter configuration is switched off.
        case disabled
        case enabled
        case failed(String)

        var title: String {
            switch self {
            case .checking: "Checking…"
            case .unavailable: "Not available in this build"
            case .notInstalled: "Not installed"
            case .installing: "Installing…"
            case .awaitingApproval: "Waiting for your approval"
            case .disabled: "Installed but turned off"
            case .enabled: "Active"
            case .failed: "Problem"
            }
        }
    }

    private(set) var status: Status = .checking {
        didSet { if status != oldValue { onStatusChange?(status) } }
    }
    @ObservationIgnored var onStatusChange: ((Status) -> Void)?
    let isEntitled: Bool
    let machServiceName: String?
    private var deactivating = false
    private var updating = false

    override init() {
        isEntitled = FilterManager.hasEntitlement("com.apple.developer.system-extension.install")
        let name = Bundle.main.object(forInfoDictionaryKey: ArgusPaths.machServiceInfoKey) as? String
        // Without a team the name starts with "." and can't be registered.
        machServiceName = name.flatMap { $0.hasPrefix(".") ? nil : $0 }
        super.init()
    }

    static func hasEntitlement(_ name: String) -> Bool {
        guard let task = SecTaskCreateFromSelf(nil) else { return false }
        return SecTaskCopyValueForEntitlement(task, name as CFString, nil) != nil
    }

    func refresh() async {
        guard isEntitled else {
            status = .unavailable
            return
        }
        let manager = NEFilterManager.shared()
        do {
            try await manager.loadFromPreferences()
            if manager.providerConfiguration == nil {
                if status != .installing, status != .awaitingApproval { status = .notInstalled }
            } else {
                status = manager.isEnabled ? .enabled : .disabled
            }
        } catch {
            status = .failed(error.localizedDescription)
        }
    }

    /// Activates the system extension; macOS may ask the user to approve it in System Settings.
    func install() {
        guard isEntitled else {
            status = .unavailable
            return
        }
        deactivating = false
        status = .installing
        let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: ArgusPaths.filterBundleIdentifier, queue: .main)
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    /// Asks macOS to swap in the filter bundled with this copy of Argus if it's a different
    /// version from the one installed. Quietly does nothing otherwise.
    func updateIfNeeded() {
        guard isEntitled, status == .enabled || status == .disabled else { return }
        updating = true
        deactivating = false
        let request = OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: ArgusPaths.filterBundleIdentifier, queue: .main)
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    func enable() async {
        let manager = NEFilterManager.shared()
        do {
            try await manager.loadFromPreferences()
            if manager.providerConfiguration == nil {
                let configuration = NEFilterProviderConfiguration()
                configuration.filterSockets = true
                configuration.filterPackets = false
                configuration.filterDataProviderBundleIdentifier = ArgusPaths.filterBundleIdentifier
                manager.providerConfiguration = configuration
                manager.localizedDescription = "Argus"
            }
            manager.isEnabled = true
            try await manager.saveToPreferences()
            status = .enabled
        } catch {
            status = .failed(error.localizedDescription)
        }
    }

    func disable() async {
        let manager = NEFilterManager.shared()
        do {
            try await manager.loadFromPreferences()
            manager.isEnabled = false
            try await manager.saveToPreferences()
            status = .disabled
        } catch {
            status = .failed(error.localizedDescription)
        }
    }

    func uninstall() async {
        let manager = NEFilterManager.shared()
        try? await manager.loadFromPreferences()
        try? await manager.removeFromPreferences()
        deactivating = true
        let request = OSSystemExtensionRequest.deactivationRequest(forExtensionWithIdentifier: ArgusPaths.filterBundleIdentifier, queue: .main)
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    fileprivate func finished() {
        if updating {
            updating = false
            return
        }
        if deactivating {
            status = .notInstalled
        } else {
            Task { await enable() }
        }
    }

    fileprivate func failed(_ error: Error) {
        let code = (error as NSError).code
        if updating {
            updating = false // the installed filter keeps running
            return
        }
        if code == OSSystemExtensionError.Code.requestCanceled.rawValue {
            status = .notInstalled
        } else if code == OSSystemExtensionError.Code.unsupportedParentBundleLocation.rawValue {
            status = .failed("Move Argus to the Applications folder, then try again.")
        } else {
            status = .failed(error.localizedDescription)
        }
    }
}

extension FilterManager: OSSystemExtensionRequestDelegate {
    nonisolated func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties,
                             withExtension replacement: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        let same = existing.bundleVersion == replacement.bundleVersion
            && existing.bundleShortVersion == replacement.bundleShortVersion
        return same ? .cancel : .replace
    }

    nonisolated func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        Task { @MainActor in self.status = .awaitingApproval }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        Task { @MainActor in self.finished() }
    }

    nonisolated func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        let error = error as NSError
        Task { @MainActor in self.failed(error) }
    }
}
