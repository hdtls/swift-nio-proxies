// swift-tools-version:5.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Netbot",
    platforms: [.macOS(.v10_14), .iOS(.v12)],
    products: [
        .library(name: "Netbot", targets: ["Netbot"]),
        .library(name: "NIOVPNProtocolHTTP", targets: ["NIOVPNProtocolHTTP"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.0.0")
    ],
    targets: [
        .target(name: "Netbot",
                dependencies: [
                    "NIO",
                    "NIOHTTP1",
                    "NIOVPNProtocolHTTP"
            ]),
        .target(name: "NIOVPNProtocolHTTP", dependencies: ["NIO", "NIOHTTP1"]),
        .testTarget(name: "NetbotTests", dependencies: ["Netbot"])
    ],
    swiftLanguageVersions: [.v5]
)
