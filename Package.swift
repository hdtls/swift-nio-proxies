// swift-tools-version:5.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "swift-nio-Netbot",
    products: [
        .library(name: "Netbot", targets: ["Netbot"]),
        .library(name: "NIOVPNProtoHTTP", targets: ["NIOVPNProtoHTTP"]),
        .library(name: "NIOVPNProtoSOCKS5", targets: ["NIOVPNProtoSOCKS5"]),
        .library(name: "NIOSecurity", targets: ["NIOSecurity"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.0.0")
    ],
    targets: [
        .target(name: "CNIOLibsodium",
                path: "Sources/CNIOLibsodium/src/libsodium",
                cSettings: [
                    .headerSearchPath("$(SRCROOT)/Sources/CNIOLibsodium/src/libsodium/include/CNIOLibsodium")
            ]),
        .target(name: "CNIOLibmbedcrypto",
                exclude: [
                    "programs"
            ],
                cSettings: [
                    .headerSearchPath("$(SRCROOT)/Sources/CNIOLibmbedcrypto/include/mbedtls"),
                    .headerSearchPath("$(SRCROOT)/Sources/CNIOLibmbedcrypto/include/psa")
            ]),
        .target(name: "CNIOSecurityShims",
                dependencies: ["CNIOLibsodium"]),
        .target(name: "NIOSecurity",
                dependencies: [
                    "CNIOLibmbedcrypto",
                    "CNIOSecurityShims"
            ]),
        .target(name: "NIOVPNProtoHTTP",
                dependencies: [
                    "NIO",
                    "NIOHTTP1"
        ]),
        .target(name: "NIOVPNProtoSOCKS5",
                dependencies: ["NIO"]),
        .target(name: "NIOVPNProtoShadowsocks",
                dependencies: [
                    "NIO",
                    "NIOSecurity",
                    "NIOVPNProtoSOCKS5"
        ]),
        .target(name: "Netbot",
                dependencies: [
                    "NIO",
                    "NIOHTTP1",
                    "NIOVPNProtoHTTP",
                    "NIOVPNProtoSOCKS5",
                    "NIOVPNProtoShadowsocks"
        ]),
        .testTarget(name: "NetbotTests",
                    dependencies: ["Netbot"]),
        .testTarget(name: "NIOVPNProtoHTTPTests",
                    dependencies: ["NIOVPNProtoHTTP"]),
        .testTarget(name: "NIOSecurityTests",
                    dependencies: ["NIOSecurity"]),
        .testTarget(name: "NIOVPNProtoShadowsocksTests",
                    dependencies: ["NIOVPNProtoShadowsocks"])
    ],
    swiftLanguageVersions: [.v5]
)
