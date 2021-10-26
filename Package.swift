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
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.0.1"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "1.1.6"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.4.2"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.32.1"),
        .package(url: "https://github.com/apple/swift-nio-ssl.git", from: "2.14.1"),
        .package(url: "https://github.com/apple/swift-nio-extras.git", from: "1.10.0"),
        .package(url: "https://github.com/apple/swift-nio-transport-services.git", from: "1.11.0"),
        .package(url: "https://github.com/vapor/async-kit.git", from: "1.9.0"),
    ],
    targets: [
        .target(name: "CMMDB",
                cSettings: [.define("HAVE_CONFIG_H")]),
        .target(name: "ConnectionPool",
                dependencies: [
                    .product(name: "Logging", package: "swift-log"),
                    .product(name: "NIOCore", package: "swift-nio"),
                    .product(name: "NIOPosix", package: "swift-nio")
                ]),
        .target(name: "Helpers",
                dependencies: [
                    .product(name: "NIO", package: "swift-nio"),
                    .product(name: "NIOHTTP1", package: "swift-nio"),
                    .product(name: "Logging", package: "swift-log")
                ]),
        .target(name: "HTTP",
                dependencies: [
                    .product(name: "ArgumentParser", package: "swift-argument-parser"),
                    .product(name: "NIO", package: "swift-nio"),
                    .product(name: "NIOHTTP1", package: "swift-nio"),
                    .product(name: "NIOSSL", package: "swift-nio-ssl"),
                    .product(name: "NIOHTTPCompression", package: "swift-nio-extras"),
                    .target(name: "ConnectionPool"),
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
        .target(name: "Netbot",
                dependencies: [
                    .product(name: "ArgumentParser", package: "swift-argument-parser"),
                    .product(name: "AsyncKit", package: "async-kit"),
                    .product(name: "NIO", package: "swift-nio"),
                    .product(name: "NIOHTTP1", package: "swift-nio"),
                    .product(name: "NIOSSL", package: "swift-nio-ssl"),
                    .product(name: "NIOExtras", package: "swift-nio-extras"),
                    .product(name: "NIOTransportServices", package: "swift-nio-transport-services"),
                    .target(name: "CMMDB"),
                    .target(name: "HTTP"),
                    .target(name: "SOCKS"),
                    .target(name: "Shadowsocks")
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
        .testTarget(name: "SOCKSTests", dependencies: [ .target(name: "SOCKS") ])
    ],
    swiftLanguageVersions: [.v5]
)
