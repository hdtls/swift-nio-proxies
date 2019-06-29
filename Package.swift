// swift-tools-version:5.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "swift-nio-Netbot",
    products: [
        .library(name: "Netbot", targets: ["Netbot"]),
        .library(name: "NIOVPNProtoHTTP", targets: ["NIOVPNProtoHTTP"]),
        .library(name: "NIOVPNProtoSOCKS5", targets: ["NIOVPNProtoSOCKS5"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.0.0")
    ],
    targets: [
        .target(name: "Netbot",
                dependencies: [
                    "NIO",
                    "NIOHTTP1",
                    "NIOVPNProtoHTTP",
                    "NIOVPNProtoSOCKS5"
            ]),
        .target(name: "NIOVPNProtoHTTP", dependencies: ["NIO", "NIOHTTP1"]),
        .target(name: "NIOVPNProtoSOCKS5", dependencies: ["NIO"]),
        .testTarget(name: "NetbotTests", dependencies: ["Netbot"]),
        .testTarget(name: "NIOVPNProtoHTTPTests", dependencies: ["NIOVPNProtoHTTP"])
    ],
    swiftLanguageVersions: [.v5]
)
