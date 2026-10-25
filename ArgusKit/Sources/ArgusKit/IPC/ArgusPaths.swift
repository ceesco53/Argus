import Foundation

public enum ArgusPaths {
    /// The filter's identifier is the app's plus ".Filter" (call from the app). The prefix is
    /// the ARGUS_BUNDLE_PREFIX build setting, so each developer team can use its own.
    public static var filterBundleIdentifier: String {
        (Bundle.main.bundleIdentifier ?? "com.argus.Argus") + ".Filter"
    }

    /// Info.plist key holding the filter's Mach service name. It embeds the team ID and the build
    /// number: during an update the old filter still owns its name while macOS registers the new
    /// one, so a shared name would leave the new filter unreachable.
    public static let machServiceInfoKey = "ArgusMachServiceName"

    /// `~/Library/Application Support/Argus` for `home` (defaults to the current user).
    public static func supportDirectory(home: String = NSHomeDirectory()) -> URL {
        URL(fileURLWithPath: home).appendingPathComponent("Library/Application Support/Argus", isDirectory: true)
    }

    /// Engine data for the in-app monitor.
    public static func monitorDirectory(home: String = NSHomeDirectory()) -> URL {
        supportDirectory(home: home).appendingPathComponent("Monitor", isDirectory: true)
    }

    /// The in-app monitor listens here for the command line tool.
    public static func monitorSocketPath(home: String = NSHomeDirectory()) -> String {
        supportDirectory(home: home).appendingPathComponent("monitor.sock").path
    }

    /// Requirement the filter imposes on clients (and clients on the filter) when signed by a team.
    public static func teamRequirement(_ teamID: String) -> String {
        "anchor apple generic and certificate leaf[subject.OU] = \"\(teamID)\""
    }
}
