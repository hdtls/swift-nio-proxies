// swift-tools-version:5.6
//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright 2021 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import PackageDescription

let swiftArgumentParser: Target.Dependency = .product(
    name: "ArgumentParser",
    package: "swift-argument-parser"
)
let swiftNIO: Target.Dependency = .product(name: "NIO", package: "swift-nio")
let swiftNIOCore: Target.Dependency = .product(name: "NIOCore", package: "swift-nio")
let swiftNIOHTTP1: Target.Dependency = .product(name: "NIOHTTP1", package: "swift-nio")
let swiftNIOPosix: Target.Dependency = .product(name: "NIOPosix", package: "swift-nio")
let swiftNIOSSL: Target.Dependency = .product(name: "NIOSSL", package: "swift-nio-ssl")
let swiftNIOTransportServices: Target.Dependency = .product(
    name: "NIOTransportServices",
    package: "swift-nio-transport-services"
)
let swiftCrypto: Target.Dependency = .product(name: "Crypto", package: "swift-crypto")
let swiftLog: Target.Dependency = .product(name: "Logging", package: "swift-log")

let package = Package(
    name: "swift-nio-netbot",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
    ],
    products: [
        .library(name: "NIODNS", targets: ["NIODNS"]),
        .library(name: "NIOHTTPMitM", targets: ["NIOHTTPMitM"]),
        .library(name: "NIOHTTPProxy", targets: ["NIOHTTPProxy"]),
        .library(name: "NIONetbot", targets: ["NIONetbot"]),
        .library(name: "NIONetbotMisc", targets: ["NIONetbotMisc"]),
        .library(name: "NIOSOCKS5", targets: ["NIOSOCKS5"]),
        .library(name: "NIOSS", targets: ["NIOSS"]),
        .library(name: "NIOTrojan", targets: ["NIOTrojan"]),
        .library(name: "NIOVMESS", targets: ["NIOVMESS"]),
        .executable(name: "netbotcli", targets: ["NetbotCLI"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.0.1"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "2.1.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.4.2"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.32.1"),
        .package(url: "https://github.com/apple/swift-nio-ssl.git", from: "2.14.1"),
        .package(url: "https://github.com/apple/swift-nio-extras.git", from: "1.10.0"),
        .package(url: "https://github.com/apple/swift-nio-transport-services.git", from: "1.11.0"),
        .package(url: "https://github.com/apple/swift-format.git", branch: "main"),
        .package(url: "https://github.com/hdtls/swift-maxminddb.git", from: "1.0.0")
    ],
    targets: [
        .target(name: "ConnectionPool", dependencies: [swiftNIOCore, swiftNIOPosix, swiftLog]),
        .target(name: "CSHAKE128"),
        .target(name: "SHAKE128", dependencies: ["CSHAKE128", "PrettyBytes", swiftCrypto]),
        .target(name: "NIODNS", dependencies: [swiftNIOCore, swiftNIOPosix]),
        .target(
            name: "NIOHTTPMitM",
            dependencies: [swiftNIOCore, swiftNIOHTTP1, swiftNIOSSL, swiftLog]
        ),
        .target(name: "NIOHTTPProxy", dependencies: ["NIONetbotMisc", swiftNIOCore, swiftNIOHTTP1]),
        .target(name: "NIONetbotMisc", dependencies: [swiftNIOCore, swiftNIOPosix]),
        .target(name: "NIOSOCKS5", dependencies: ["NIONetbotMisc", swiftNIOCore]),
        .target(
            name: "NIOSS",
            dependencies: ["NIONetbotMisc", "PrettyBytes", swiftCrypto, swiftNIOCore]
        ),
        .target(
            name: "NIOTrojan",
            dependencies: ["NIONetbotMisc", "PrettyBytes", swiftCrypto, swiftNIOCore, swiftNIOSSL]
        ),
        .target(
            name: "NIOVMESS",
            dependencies: ["NIONetbotMisc", "PrettyBytes", "SHAKE128", swiftCrypto, swiftNIOCore]
        ),
        .target(
            name: "NIONetbot",
            dependencies: [
                "ConnectionPool",
                "NIONetbotMisc",
                "NIODNS",
                "NIOHTTPProxy",
                "NIOHTTPMitM",
                "NIOSOCKS5",
                "NIOSS",
                "NIOTrojan",
                "NIOVMESS",
                swiftCrypto,
                swiftNIOCore,
                swiftNIOPosix,
                swiftLog,
                swiftNIOSSL,
                swiftNIOHTTP1,
                swiftNIOTransportServices,
                .product(name: "NIOConcurrencyHelpers", package: "swift-nio"),
                .product(name: "NIOHTTPCompression", package: "swift-nio-extras"),
                .product(name: "NIOExtras", package: "swift-nio-extras")
            ]
        ),
        .target(name: "PrettyBytes"),
        .target(
            name: "NetbotCLICore",
            dependencies: [
                "NIONetbot",
                swiftArgumentParser,
                swiftLog,
                .product(name: "MaxMindDB", package: "swift-maxminddb")
            ]
        ),
        .executableTarget(
            name: "NetbotCLI",
            dependencies: ["NetbotCLICore", swiftArgumentParser, swiftLog]
        ),
        .testTarget(name: "NIOHTTPMitMTests", dependencies: ["NIOHTTPMitM", swiftNIO]),
        .testTarget(name: "NIONetbotMiscTests", dependencies: ["NIONetbotMisc", swiftNIO]),
        .testTarget(
            name: "NIOHTTPProxyTests",
            dependencies: ["NIOHTTPProxy", swiftNIO, swiftNIOHTTP1, swiftNIOSSL]
        ),
        .testTarget(name: "NIOTrojanTests", dependencies: ["NIOTrojan", "PrettyBytes", swiftNIO]),
        .testTarget(name: "SHAKE128Tests", dependencies: ["SHAKE128"]),
        .testTarget(name: "NIOSOCKS5Tests", dependencies: ["NIOSOCKS5", swiftNIO]),
        .testTarget(
            name: "NIOSSTests",
            dependencies: ["PrettyBytes", "NIOSS", swiftNIO],
            exclude: [
                "RequestEncoderTests.g.swift.gyb",
                "ResponseDecoderTests.g.swift.gyb"
            ]
        ),
        .testTarget(name: "NIOVMESSTests", dependencies: ["PrettyBytes", "NIOVMESS", swiftNIO]),
        .testTarget(
            name: "NIONetbotTests",
            dependencies: [
                "NIONetbot",
                "NIONetbotMisc",
                "NIOHTTPProxy",
                "NIOSOCKS5",
                "NIOSS",
                "NIOVMESS",
                swiftNIO,
                swiftNIOSSL,
                swiftNIOHTTP1,
                swiftNIOTransportServices
            ]
        ),
        .testTarget(
            name: "NetbotCLICoreTests",
            dependencies: [
                "NetbotCLICore",
                swiftNIO
            ],
            exclude: ["ParsableRuleTests.g.swift.gyb"]
        )
    ],
    swiftLanguageVersions: [.v5]
)
