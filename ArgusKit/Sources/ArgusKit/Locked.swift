import Foundation

/// A lock-protected box. Network Extension callbacks arrive on arbitrary queues and
/// must be answered synchronously, so shared engine state lives behind one of these
/// rather than inside an actor.
public final class Locked<Value>: @unchecked Sendable {
    private var value: Value
    private let lock = NSLock()

    public init(_ value: Value) { self.value = value }

    @discardableResult
    public func withLock<R>(_ body: (inout Value) throws -> R) rethrows -> R {
        lock.lock()
        defer { lock.unlock() }
        return try body(&value)
    }

    public var current: Value { withLock { $0 } }
}

extension Array where Element: Comparable {
    /// Binary search in an ascending, duplicate-free array.
    func sortedContains(_ element: Element) -> Bool {
        var low = 0, high = count - 1
        while low <= high {
            let mid = (low + high) / 2
            let candidate = self[mid]
            if candidate == element { return true }
            if candidate < element { low = mid + 1 } else { high = mid - 1 }
        }
        return false
    }
}
