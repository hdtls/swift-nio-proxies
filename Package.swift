// swift-tools-version:5.4
//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright  2021 Junfeng Zhang. and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import PackageDescription

let package = Package(
    name: "swift-nio-netbot",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
    ],
    products: [
        .library(name: "Netbot", targets: ["Netbot"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "1.1.6"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.4.2"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.32.1"),
        .package(url: "https://github.com/apple/swift-nio-ssl.git", from: "2.14.1"),
        .package(url: "https://github.com/apple/swift-nio-extras.git", from: "1.10.0")
    ],
    targets: [
        .target(name: "Helpers",
                dependencies: [
                    .product(name: "NIO", package: "swift-nio"),
                    .product(name: "NIOHTTP1", package: "swift-nio"),
                    .product(name: "Logging", package: "swift-log")
                ]),
        .target(name: "HTTP",
                dependencies: [
                    .product(name: "NIO", package: "swift-nio"),
                    .product(name: "NIOHTTP1", package: "swift-nio"),
                    .product(name: "NIOSSL", package: "swift-nio-ssl"),
                    .target(name: "Helpers")
                ]),
        .target(name: "SOCKS",
                dependencies: [
                    .product(name: "NIO", package: "swift-nio"),
                    .product(name: "NIOSSL", package: "swift-nio-ssl"),
                    .target(name: "Helpers")
                ]),
        .target(name: "Shadowsocks",
                dependencies: [
                    .product(name: "Crypto", package: "swift-crypto"),
                    .product(name: "NIO", package: "swift-nio"),
                    .target(name: "Helpers")
                ]),
        .target(name: "VMESS",
               dependencies: [
                    .product(name: "Crypto", package: "swift-crypto"),
                    .product(name: "NIO", package: "swift-nio"),
                    .product(name: "NIOWebSocket", package: "swift-nio"),
                    .target(name: "Helpers")
               ]),
        .target(name: "Netbot",
                dependencies: [
                    .product(name: "NIO", package: "swift-nio"),
                    .product(name: "NIOHTTP1", package: "swift-nio"),
                    .product(name: "NIOSSL", package: "swift-nio-ssl"),
                    .target(name: "HTTP"),
                    .target(name: "SOCKS"),
                    .target(name: "Shadowsocks"),
                    .target(name: "VMESS")
                ]),
        .executableTarget(name: "Linking",
                          dependencies: [
                            .product(name: "NIO", package: "swift-nio"),
                            .product(name: "NIOSSL", package: "swift-nio-ssl"),
                            .product(name: "NIOSOCKS", package: "swift-nio-extras"),
                            .product(name: "Logging", package: "swift-log"),
                            .target(name: "Netbot")
                          ]),
        .testTarget(name: "HelperTests", dependencies: [ .product(name: "NIOCore", package: "swift-nio"), .target(name: "Helpers") ]),
        .testTarget(name: "NetbotTests", dependencies: [ .product(name: "NIOEmbedded", package: "swift-nio"), .target(name: "Netbot") ]),
        .testTarget(name: "SOCKSTests", dependencies: [ .target(name: "SOCKS") ]),
        .testTarget(name: "VMESSTests", dependencies: [ .target(name: "VMESS") ])
    ],
    swiftLanguageVersions: [.v5]
)
