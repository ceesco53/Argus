import Foundation

/// Files the engine keeps on disk. Everything is private to the engine's user (root for the
/// network extension).
public final class StateStore: Sendable {
    public let directory: URL

    public init(directory: URL) {
        self.directory = directory
        let fm = FileManager.default
        for dir in [directory, groupsDirectory, capturesDirectory] {
            try? fm.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        }
    }

    var stateURL: URL { directory.appendingPathComponent("state.json") }
    var activityURL: URL { directory.appendingPathComponent("activity.json") }
    var groupsDirectory: URL { directory.appendingPathComponent("RuleGroups", isDirectory: true) }
    public var capturesDirectory: URL { directory.appendingPathComponent("Captures", isDirectory: true) }

    public func loadState() -> FirewallState? {
        guard let data = try? Data(contentsOf: stateURL) else { return nil }
        return try? Self.decoder.decode(FirewallState.self, from: data)
    }

    public func saveState(_ state: FirewallState) throws {
        try write(Self.encoder.encode(state), to: stateURL)
    }

    func loadBlocklist(_ id: UUID) -> CompiledBlocklist? {
        guard let data = try? Data(contentsOf: groupsDirectory.appendingPathComponent("\(id.uuidString).set")) else { return nil }
        return CompiledBlocklist(serialized: data)
    }

    func saveBlocklist(_ list: CompiledBlocklist, id: UUID) throws {
        try write(list.serialized(), to: groupsDirectory.appendingPathComponent("\(id.uuidString).set"))
    }

    private func referenceURL(_ id: String) -> URL { groupsDirectory.appendingPathComponent("\(id).set") }

    func loadReference(_ id: String) -> CompiledBlocklist? {
        (try? Data(contentsOf: referenceURL(id))).flatMap(CompiledBlocklist.init(serialized:))
    }

    func saveReference(_ list: CompiledBlocklist, id: String) throws {
        try write(list.serialized(), to: referenceURL(id))
    }

    /// When the reference list was last downloaded.
    func referenceDate(_ id: String) -> Date? {
        (try? referenceURL(id).resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate
    }

    func deleteBlocklist(_ id: UUID) {
        try? FileManager.default.removeItem(at: groupsDirectory.appendingPathComponent("\(id.uuidString).set"))
    }

    func loadActivity() -> Data? { try? Data(contentsOf: activityURL) }

    func saveActivity(_ data: Data) { try? write(data, to: activityURL) }

    private func write(_ data: Data, to url: URL) throws {
        try data.write(to: url, options: [.atomic])
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }()

    static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }()
}
