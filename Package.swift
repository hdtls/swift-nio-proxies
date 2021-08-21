// swift-tools-version:5.4
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "swift-nio-netbot",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
    ],
    products: [
//        .executable(name: "Run", targets: ["Run"]),
        .library(name: "Netbot", targets: ["Netbot"]),
        .library(name: "NIOVPNProtoHTTP", targets: ["NIOVPNProtoHTTP"]),
        .library(name: "NIOVPNProtoSOCKS5", targets: ["NIOVPNProtoSOCKS5"]),
        .library(name: "NIOSecurity", targets: ["NIOSecurity"]),
        .library(name: "CNELibsscrypto", targets: ["CNELibsscrypto"]),
        .library(name: "CNELibmbedcrypto", targets: ["CNELibmbedcrypto"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.32.1"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "1.1.6"),
    ],
    targets: [
        .systemLibrary(
            name: "CNELibsodiumcrypto",
            pkgConfig: "libsodium",
            providers: [
                .brew(["libsodium"]),
                .apt(["libsodium-dev"])
            ]
        ),
        .target(name: "CNELibmbedcrypto"),
        .target(name: "CNESecurityShims",
                dependencies: [
                    .target(name: "CNELibsodiumcrypto"),
                ]),
        .target(name: "CNELibsscrypto",
                dependencies: [
                    .target(name: "CNELibsodiumcrypto"),
                    .target(name: "CNELibmbedcrypto")
                ]),
        .target(name: "NIOSecurity",
                dependencies: [
                    .product(name: "Crypto", package: "swift-crypto"),
                    .target(name: "CNELibmbedcrypto"),
                    .target(name: "CNESecurityShims"),
                ]),
        .target(name: "NIOVPNProtoHTTP",
                dependencies: [
                    .product(name: "NIO", package: "swift-nio"),
                    .product(name: "NIOHTTP1", package: "swift-nio")
                ]),
        .target(name: "NIOVPNProtoSOCKS5",
                dependencies: [
                    .product(name: "NIO", package: "swift-nio")
                ]),
        .target(name: "NIOVPNProtoShadowsocks",
                dependencies: [
                    .product(name: "NIO", package: "swift-nio"),
                    .product(name: "Crypto", package: "swift-crypto"),
                    .target(name: "NIOSecurity"),
                    .target(name: "NIOVPNProtoSOCKS5")
                ]),
        .target(name: "Netbot",
                dependencies: [
                    .product(name: "NIO", package: "swift-nio"),
                    .product(name: "NIOHTTP1", package: "swift-nio"),
                    .target(name: "NIOVPNProtoHTTP"),
                    .target(name: "NIOVPNProtoSOCKS5"),
                    .target(name: "NIOVPNProtoShadowsocks")
                ]),
        .testTarget(name: "NetbotTests",
                    dependencies: [
                        .target(name: "Netbot")
                    ]),
        .testTarget(name: "NIOVPNProtoHTTPTests",
                    dependencies: [
                        .target(name: "NIOVPNProtoHTTP")
                    ]),
        .testTarget(name: "NIOSecurityTests",
                    dependencies: [
                        .target(name: "NIOSecurity"),
                        .product(name: "Crypto", package: "swift-crypto")
                    ]),
        .testTarget(name: "NIOVPNProtoShadowsocksTests",
                    dependencies: [.target(name: "NIOVPNProtoShadowsocks")
                    ])
    ],
    swiftLanguageVersions: [.v5]
)
