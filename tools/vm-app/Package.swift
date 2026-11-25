// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "VirtualGrinderApp",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "VirtualGrinderApp",
            path: "Sources/VirtualGrinderApp"
        )
    ]
)
