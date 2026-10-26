import ArgusKit
import Foundation
import NetworkExtension
import Observation
import OSLog
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
    private var resaving = false
    nonisolated static let log = Logger(subsystem: Bundle.main.bundleIdentifier ?? "Argus", category: "filter")

    /// The filter requirement the configuration carried when this app last saved it.
    private static let savedRequirementKey = "filterConfigurationRequirement"

    /// The code requirement of the filter bundled in this copy of Argus. macOS records it when the
    /// filter configuration is saved, and won't start a filter that doesn't satisfy it.
    static let bundledFilterRequirement: String? = {
        let url = Bundle.main.bundleURL
            .appendingPathComponent("Contents/Library/SystemExtensions/\(ArgusPaths.filterBundleIdentifier).systemextension")
        var code: SecStaticCode?
        var requirement: SecRequirement?
        var text: CFString?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess, let code,
              SecCodeCopyDesignatedRequirement(code, [], &requirement) == errSecSuccess, let requirement,
              SecRequirementCopyString(requirement, [], &text) == errSecSuccess else { return nil }
        return text as String?
    }()

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
                if manager.isEnabled, await !saveAgainIfSignatureChanged(manager) { return } // status says why
                status = manager.isEnabled ? .enabled : .disabled
            }
        } catch {
            status = .failed(error.localizedDescription)
        }
    }

    /// An update signed differently (a Developer ID release replacing a development build, or a new
    /// certificate) leaves macOS holding the old signature, and it refuses to start the new filter
    /// ("does not satisfy the code signature requirements"). Switching the configuration off and on
    /// records the new signature. Only the copy in Applications does this, so a development build
    /// run from elsewhere can't take the configuration over.
    /// Returns false when the filter couldn't be switched back on (and says so in `status`).
    private func saveAgainIfSignatureChanged(_ manager: NEFilterManager) async -> Bool {
        guard !resaving, Bundle.main.bundleURL.path.hasPrefix("/Applications/"),
              let requirement = FilterManager.bundledFilterRequirement,
              UserDefaults.standard.string(forKey: FilterManager.savedRequirementKey) != requirement else { return true }
        resaving = true
        defer { resaving = false }
        manager.isEnabled = false
        do {
            try await manager.saveToPreferences()
        } catch {
            manager.isEnabled = true // nothing changed; try again next time
            return true
        }
        manager.isEnabled = true
        for attempt in 1...3 {
            do {
                try await manager.saveToPreferences()
                UserDefaults.standard.set(requirement, forKey: FilterManager.savedRequirementKey)
                FilterManager.log.info("Saved the filter configuration again for a new code signature")
                return true
            } catch where attempt < 3 {
                FilterManager.log.error("Saving the filter configuration failed, trying again: \(error.localizedDescription, privacy: .public)")
                try? await Task.sleep(for: .seconds(1))
            } catch {
                status = .failed("Argus couldn't turn its network filter back on: \(error.localizedDescription)")
            }
        }
        return false
    }

    private func recordSavedSignature() {
        UserDefaults.standard.set(FilterManager.bundledFilterRequirement, forKey: FilterManager.savedRequirementKey)
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
            recordSavedSignature()
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
            recordSavedSignature()
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
            // macOS may have passed through "needs approval" on the way (it does when the new filter
            // is signed differently, then reuses the earlier approval), so look again rather than
            // keep whatever the status was last set to.
            FilterManager.log.info("Filter update finished")
            updating = false
            Task { await refresh() }
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
            FilterManager.log.error("Filter update failed: \(error.localizedDescription, privacy: .public)")
            updating = false // the installed filter keeps running
            Task { await refresh() }
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
        FilterManager.log.info("The filter request needs approval")
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
