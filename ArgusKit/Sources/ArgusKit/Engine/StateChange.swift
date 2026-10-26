import Foundation

/// The difference a request made to the configuration, kept so it can be undone later.
///
/// Only the touched items are stored, and undo restores exactly those, so undoing an older
/// change doesn't throw away unrelated changes made since. Settings are compared field by field
/// for the same reason.
struct StateChange: Sendable {
    /// Each touched item's value before and after; nil means it didn't exist.
    var rules: [UUID: (before: Rule?, after: Rule?)] = [:]
    var profiles: [UUID: (before: Profile?, after: Profile?)] = [:]
    var groups: [UUID: (before: RuleGroup?, after: RuleGroup?)] = [:]
    var knownNetworks: (before: [NetworkIdentity], after: [NetworkIdentity])?
    /// The changed settings fields, as they were (absent keys were nil).
    var settingsBefore: [String: JSONValue] = [:]
    var changedSettings: [String] = []

    var isEmpty: Bool {
        rules.isEmpty && profiles.isEmpty && groups.isEmpty && knownNetworks == nil && changedSettings.isEmpty
    }

    static func between(_ old: FirewallState, _ new: FirewallState) -> StateChange? {
        var change = StateChange()
        change.rules = diff(old.rules, new.rules)
        change.profiles = diff(old.profiles, new.profiles)
        // Download bookkeeping (counts, dates, errors) isn't a configuration change.
        change.groups = diff(old.ruleGroups, new.ruleGroups) { $0.configuration == $1.configuration }
        if old.knownNetworks != new.knownNetworks { change.knownNetworks = (old.knownNetworks, new.knownNetworks) }
        let before = JSONValue.fields(of: old.settings), after = JSONValue.fields(of: new.settings)
        change.changedSettings = Set(before.keys).union(after.keys).filter { before[$0] != after[$0] }.sorted()
        change.settingsBefore = before.filter { change.changedSettings.contains($0.key) }
        return change.isEmpty ? nil : change
    }

    private static func diff<T: Identifiable & Equatable>(
        _ old: [T], _ new: [T], same: (T, T) -> Bool = { $0 == $1 }
    ) -> [T.ID: (before: T?, after: T?)] where T.ID == UUID {
        let oldByID = Dictionary(old.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        let newByID = Dictionary(new.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        var result: [UUID: (before: T?, after: T?)] = [:]
        for id in Set(oldByID.keys).union(newByID.keys) {
            switch (oldByID[id], newByID[id]) {
            case let (a?, b?) where same(a, b): continue
            case let (a, b): result[id] = (a, b)
            }
        }
        return result
    }

    /// Puts every touched item back the way it was before the change.
    func undo(on state: inout FirewallState) {
        Self.restore(rules, in: &state.rules)
        Self.restore(profiles, in: &state.profiles)
        Self.restore(groups, in: &state.ruleGroups)
        if let knownNetworks { state.knownNetworks = knownNetworks.before }
        if !changedSettings.isEmpty {
            var fields = JSONValue.fields(of: state.settings)
            for key in changedSettings { fields[key] = settingsBefore[key] }
            if let restored = JSONValue.decode(FirewallSettings.self, from: fields) { state.settings = restored }
        }
    }

    private static func restore<T: Identifiable>(_ touched: [UUID: (before: T?, after: T?)], in items: inout [T]) where T.ID == UUID {
        for (id, values) in touched {
            if let before = values.before {
                if let index = items.firstIndex(where: { $0.id == id }) { items[index] = before } else { items.append(before) }
            } else {
                items.removeAll { $0.id == id }
            }
        }
    }

    /// Rules the change added, and the ones it removed.
    var addedRules: [Rule] { rules.values.compactMap { $0.before == nil ? $0.after : nil } }
    var removedRules: [Rule] { rules.values.compactMap { $0.after == nil ? $0.before : nil } }
}

extension RuleGroup {
    /// What the user chose, as opposed to what downloading filled in.
    struct Configuration: Equatable {
        var name: String
        var url: URL?
        var isEnabled: Bool
        var format: BlocklistFormat
        var updateInterval: TimeInterval
    }

    var configuration: Configuration {
        Configuration(name: name, url: url, isEnabled: isEnabled, format: format, updateInterval: updateInterval)
    }
}

/// A JSON value, used to compare and restore individual settings fields generically.
enum JSONValue: Equatable, Sendable, Codable {
    case string(String), number(Double), bool(Bool), null
    case array([JSONValue]), object([String: JSONValue])

    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null }
        else if let b = try? c.decode(Bool.self) { self = .bool(b) }
        else if let n = try? c.decode(Double.self) { self = .number(n) }
        else if let s = try? c.decode(String.self) { self = .string(s) }
        else if let a = try? c.decode([JSONValue].self) { self = .array(a) }
        else { self = .object(try c.decode([String: JSONValue].self)) }
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .string(let s): try c.encode(s)
        case .number(let n): try c.encode(n)
        case .bool(let b): try c.encode(b)
        case .null: try c.encodeNil()
        case .array(let a): try c.encode(a)
        case .object(let o): try c.encode(o)
        }
    }

    static func fields<T: Encodable>(of value: T) -> [String: JSONValue] {
        guard let data = try? JSONEncoder().encode(value), case .object(let fields)? = try? JSONDecoder().decode(JSONValue.self, from: data) else { return [:] }
        return fields
    }

    static func decode<T: Decodable>(_ type: T.Type, from fields: [String: JSONValue]) -> T? {
        guard let data = try? JSONEncoder().encode(JSONValue.object(fields)) else { return nil }
        return try? JSONDecoder().decode(type, from: data)
    }
}
