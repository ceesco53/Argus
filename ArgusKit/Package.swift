// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "ArgusKit",
    platforms: [.macOS(.v15)],
    products: [
        .library(name: "ArgusKit", targets: ["ArgusKit"]),
    ],
    targets: [
        .target(
            name: "ArgusKit",
            linkerSettings: [.linkedFramework("Security"), .linkedFramework("SystemConfiguration")]
        ),
        .testTarget(name: "ArgusKitTests", dependencies: ["ArgusKit"]),
    ]
)
