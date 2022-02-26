// swift-tools-version:5.4
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
        .library(name: "Netbot", targets: ["Netbot"]),
        .executable(name: "netbotcli", targets: ["NetbotCLI"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.0.1"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "1.1.6"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.4.2"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.32.1"),
        .package(url: "https://github.com/apple/swift-nio-ssl.git", from: "2.14.1"),
        .package(url: "https://github.com/apple/swift-nio-extras.git", from: "1.10.0"),
        .package(url: "https://github.com/apple/swift-nio-transport-services.git", from: "1.11.0")
    ],
    targets: [
        .target(name: "CTinySHA3"),
        .target(name: "SHAKE128",
                dependencies: [
                    "CTinySHA3",
                    .product(name: "Crypto", package: "swift-crypto")
                ]),
        .target(name: "CMMDB",
                cSettings: [.define("HAVE_CONFIG_H")]),
        .target(name: "ConnectionPool",
                dependencies: [
                    .product(name: "Logging", package: "swift-log"),
                    .product(name: "NIOCore", package: "swift-nio"),
                    .product(name: "NIOPosix", package: "swift-nio")
                ]),
        .target(name: "NetbotHelpers",
                dependencies: [
                    .product(name: "NIOCore", package: "swift-nio"),
                    .product(name: "NIOHTTP1", package: "swift-nio"),
                    .product(name: "Logging", package: "swift-log")
                ]),
        .target(name: "NetbotHTTP",
                dependencies: [
                    "NetbotHelpers",
                    "ConnectionPool",
                    .product(name: "ArgumentParser", package: "swift-argument-parser"),
                    .product(name: "NIOCore", package: "swift-nio"),
                    .product(name: "NIOHTTP1", package: "swift-nio"),
                    .product(name: "NIOSSL", package: "swift-nio-ssl"),
                    .product(name: "NIOHTTPCompression", package: "swift-nio-extras"),
                ]),
        .target(name: "NetbotSOCKS",
                dependencies: [
                    "NetbotHelpers",
                    .product(name: "NIOCore", package: "swift-nio"),
                    .product(name: "NIOSSL", package: "swift-nio-ssl"),
                ]),
        .target(name: "NetbotSS",
                dependencies: [
                    "NetbotHelpers",
                    .product(name: "Crypto", package: "swift-crypto"),
                    .product(name: "NIOCore", package: "swift-nio"),
                ]),
        .target(name: "NetbotVMESS",
                dependencies: [
                    "NetbotHelpers",
                    "SHAKE128",
                    .product(name: "Crypto", package: "swift-crypto"),
                    .product(name: "NIOCore", package: "swift-nio"),
                    .product(name: "NIOWebSocket", package: "swift-nio")
                ]),
        .target(name: "Netbot",
                dependencies: [
                    "CMMDB",
                    "NetbotHTTP",
                    "NetbotSOCKS",
                    "NetbotSS",
                    "NetbotVMESS",
                    .product(name: "ArgumentParser", package: "swift-argument-parser"),
                    .product(name: "NIOCore", package: "swift-nio"),
                    .product(name: "NIOHTTP1", package: "swift-nio"),
                    .product(name: "NIOSSL", package: "swift-nio-ssl"),
                    .product(name: "NIOExtras", package: "swift-nio-extras"),
                    .product(name: "NIOTransportServices", package: "swift-nio-transport-services"),
                ]),
        .executableTarget(name: "NetbotCLI",
                          dependencies: [
                            "Netbot",
                            .product(name: "ArgumentParser", package: "swift-argument-parser")
                          ]),
        .testTarget(name: "NetbotHelpersTests",
                    dependencies: [
                        "NetbotHelpers",
                        .product(name: "NIO", package: "swift-nio")
                    ]),
        .testTarget(name: "NetbotTests",
                    dependencies: [
                        "Netbot",
                        "NetbotHTTP",
                        "NetbotSOCKS",
                        "NetbotSS",
                        "NetbotVMESS",
                        .product(name: "NIO", package: "swift-nio"),
                        .product(name: "NIOHTTP1", package: "swift-nio"),
                        .product(name: "NIOSSL", package: "swift-nio-ssl"),
                        .product(name: "NIOExtras", package: "swift-nio-extras"),
                        .product(name: "NIOTransportServices", package: "swift-nio-transport-services")
                    ]),
        .testTarget(name: "SHAKE128Tests",
                    dependencies: [ "SHAKE128" ]),
        .testTarget(name: "NetbotSOCKSTests",
                    dependencies: [ "NetbotSOCKS" ]),
        .testTarget(name: "NetbotVMESSTests",
                    dependencies: [ "NetbotVMESS" ])
    ],
    swiftLanguageVersions: [.v5]
)
