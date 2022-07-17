// swift-tools-version:5.6
//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright 2021 Junfeng Zhang. and the Netbot project authors
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
        .library(name: "NIONetbot", targets: ["NIONetbot"]),
        .executable(name: "netbotcli", targets: ["NIONetbotCLI"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.0.1"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "1.1.6"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.4.2"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.32.1"),
        .package(url: "https://github.com/apple/swift-nio-ssl.git", from: "2.14.1"),
        .package(url: "https://github.com/apple/swift-nio-extras.git", from: "1.10.0"),
        .package(url: "https://github.com/apple/swift-nio-transport-services.git", from: "1.11.0"),
        .package(url: "https://github.com/hdtls/swift-maxminddb.git", from: "1.0.0"),
    ],
    targets: [
        .target(
            name: "ConnectionPool",
            dependencies: [
                .product(name: "Logging", package: "swift-log"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
            ]
        ),
        .target(name: "CSHAKE128"),
        .target(
            name: "SHAKE128",
            dependencies: [
                "CSHAKE128",
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .target(
            name: "NIODNS",
            dependencies: [
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
            ]
        ),
        .target(
            name: "NIOHTTPMitM",
            dependencies: [
                .product(name: "Logging", package: "swift-log"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOHTTPCompression", package: "swift-nio-extras"),
            ]
        ),
        .target(
            name: "NIOHTTPProxy",
            dependencies: [
                "NIONetbotMisc",
                "ConnectionPool",
                "NIOHTTPMitM",
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
            ]
        ),
        .target(
            name: "NIONetbot",
            dependencies: [
                "NIONetbotMisc",
                "NIODNS",
                "NIOHTTPProxy",
                "NIOSOCKS5",
                "NIOSS",
                "NIOTrojan",
                "NIOVMESS",
                .product(name: "MaxMindDB", package: "swift-maxminddb"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "NIOExtras", package: "swift-nio-extras"),
                .product(name: "NIOTransportServices", package: "swift-nio-transport-services"),
            ]
        ),
        .target(
            name: "NIONetbotMisc",
            dependencies: [
                .product(name: "Logging", package: "swift-log"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
            ]
        ),
        .target(
            name: "NIOSOCKS5",
            dependencies: [
                "NIONetbotMisc",
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
            ]
        ),
        .target(
            name: "NIOSS",
            dependencies: [
                "NIONetbotMisc",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "NIOCore", package: "swift-nio"),
            ]
        ),
        .target(
            name: "NIOTrojan",
            dependencies: [
                "NIONetbotMisc",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
            ]
        ),
        .target(
            name: "NIOVMESS",
            dependencies: [
                "NIONetbotMisc",
                "SHAKE128",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOWebSocket", package: "swift-nio"),
            ]
        ),
        .executableTarget(
            name: "NIONetbotCLI",
            dependencies: [
                "NIONetbot",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ]
        ),
        .testTarget(
            name: "NIONetbotTests",
            dependencies: [
                "NIONetbot",
                "NIONetbotMisc",
                "NIOHTTPProxy",
                "NIOSOCKS5",
                "NIOSS",
                "NIOVMESS",
                .product(name: "NIO", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "NIOTransportServices", package: "swift-nio-transport-services"),
            ],
            exclude: ["RuleTests.swift.gyb"]
        ),
        .testTarget(
            name: "NIONetbotMiscTests",
            dependencies: [
                "NIONetbotMisc",
                .product(name: "NIO", package: "swift-nio"),
            ]
        ),
        .testTarget(
            name: "NIOHTTPProxyTests",
            dependencies: [
                "NIOHTTPProxy",
                .product(name: "NIO", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
            ]
        ),
        .testTarget(
            name: "NIOTrojanTests",
            dependencies: [
                "NIOTrojan"
            ]
        ),
        .testTarget(
            name: "SHAKE128Tests",
            dependencies: ["SHAKE128"]
        ),
        .testTarget(
            name: "NIOSOCKS5Tests",
            dependencies: [
                "NIOSOCKS5",
                .product(name: "NIOEmbedded", package: "swift-nio"),
            ]
        ),
        .testTarget(
            name: "NIOVMESSTests",
            dependencies: ["NIOVMESS"]
        ),
    ],
    swiftLanguageVersions: [.v5]
)
