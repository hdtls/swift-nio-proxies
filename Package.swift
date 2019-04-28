// swift-tools-version:5.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Netbot",
    platforms: [.macOS(.v10_14), .iOS(.v12)],
    products: [
        .library(name: "Netbot", targets: ["Netbot"]),
        .library(name: "NIOVPNProtocolHTTP", targets: ["NIOVPNProtocolHTTP"]),
        .library(name: "NIOVPNProtocolSOCKS5", targets: ["NIOVPNProtocolSOCKS5"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.0.0")
    ],
    targets: [
        .target(name: "Netbot",
                dependencies: [
                    "NIO",
                    "NIOHTTP1",
                    "NIOVPNProtocolHTTP",
                    "NIOVPNProtocolSOCKS5"
            ]),
        .target(name: "NIOVPNProtocolHTTP", dependencies: ["NIO", "NIOHTTP1"]),
        .target(name: "NIOVPNProtocolSOCKS5", dependencies: ["NIO"]),
        .testTarget(name: "NetbotTests", dependencies: ["Netbot"]),
        .testTarget(name: "NIOVPNProtocolHTTPTests", dependencies: ["NIOVPNProtocolHTTP"])
    ],
    swiftLanguageVersions: [.v5]
)
