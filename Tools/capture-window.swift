// Captures only the windows of one app (no other screen content).
// Usage: swift Tools/capture-window.swift <owner name> <output.png> [title | --smallest | --list]
import CoreGraphics
import Foundation

let arguments = CommandLine.arguments
let owner = arguments[1]
let output = arguments[2]
let selector = arguments.count > 3 ? arguments[3] : nil

func area(_ w: [String: Any]) -> Double {
    let b = w[kCGWindowBounds as String] as? [String: Double] ?? [:]
    return (b["Width"] ?? 0) * (b["Height"] ?? 0)
}

let windows = (CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]]) ?? []
let mine = windows.filter { ($0[kCGWindowOwnerName as String] as? String) == owner && area($0) > 10_000 }
if selector == "--list" {
    for w in mine { print(w[kCGWindowNumber as String]!, w[kCGWindowLayer as String]!, w[kCGWindowName as String] ?? "-", w[kCGWindowBounds as String]!) }
    exit(0)
}
let chosen: [String: Any]? = switch selector {
case nil: mine.max { area($0) < area($1) }
case "--smallest": mine.min { area($0) < area($1) }
case let title?: mine.first { ($0[kCGWindowName as String] as? String)?.contains(title) == true }
}
guard let chosen, let id = chosen[kCGWindowNumber as String] as? Int else {
    print("no window")
    exit(1)
}
let task = Process()
task.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
task.arguments = ["-x", "-o", "-l\(id)", output]
try task.run()
task.waitUntilExit()
print("captured window \(id)")
