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
        .package(url: "https://github.com/apple/swift-nio-transport-services.git", from: "1.11.0"),
        .package(url: "https://github.com/hdtls/swift-preference.git", from: "1.0.0"),
        .package(url: "https://github.com/hdtls/swift-erase-nil-decoding.git", .revision("fc7ac89dd33f353222e610a1d8253e70dc4a1169"))
    ],
    targets: [
        .target(name: "CSHAKE128"),
        .target(name: "SHAKE128",
                dependencies: [
                    "CSHAKE128",
                    .product(name: "Crypto", package: "swift-crypto")
                ]),
        .target(name: "CMaxMindDB",
                cSettings: [
                    .define("PACKAGE_VERSION", to: "\"1.6.0\""),
                    // cmake CheckTypeSize
                    .define("MMDB_UINT128_USING_MODE", to: "0"),
                    .define("MMDB_UINT128_IS_BYTE_ARRAY", to: "0"),
                    // cmake TestBigEndian
                    .define("MMDB_LITTLE_ENDIAN"),
                ]
               ),
        .target(name: "ConnectionPool",
                dependencies: [
                    .product(name: "Logging", package: "swift-log"),
                    .product(name: "NIOCore", package: "swift-nio"),
                    .product(name: "NIOPosix", package: "swift-nio")
                ]),
        .target(name: "MaxMindDB",
                dependencies: [ "CMaxMindDB" ]),
        .target(name: "NetbotCore",
                dependencies: [
                    .product(name: "Logging", package: "swift-log"),
                    .product(name: "NIOCore", package: "swift-nio"),
                    .product(name: "NIOPosix", package: "swift-nio")
                ]),
        .target(name: "NetbotHTTP",
                dependencies: [
                    "NetbotCore",
                    "ConnectionPool",
                    .product(name: "ArgumentParser", package: "swift-argument-parser"),
                    .product(name: "NIOCore", package: "swift-nio"),
                    .product(name: "NIOHTTP1", package: "swift-nio"),
                    .product(name: "NIOSSL", package: "swift-nio-ssl"),
                    .product(name: "NIOHTTPCompression", package: "swift-nio-extras"),
                ]),
        .target(name: "NetbotSOCKS",
                dependencies: [
                    "NetbotCore",
                    .product(name: "NIOCore", package: "swift-nio"),
                    .product(name: "NIOSSL", package: "swift-nio-ssl"),
                ]),
        .target(name: "NetbotSS",
                dependencies: [
                    "NetbotCore",
                    .product(name: "Crypto", package: "swift-crypto"),
                    .product(name: "NIOCore", package: "swift-nio"),
                ]),
        .target(name: "NetbotTrojan",
                dependencies: [
                    "NetbotCore",
                    .product(name: "Crypto", package: "swift-crypto"),
                    .product(name: "Logging", package: "swift-log"),
                    .product(name: "NIOCore", package: "swift-nio")
                ]),
        .target(name: "NetbotVMESS",
                dependencies: [
                    "NetbotCore",
                    "SHAKE128",
                    .product(name: "Crypto", package: "swift-crypto"),
                    .product(name: "NIOCore", package: "swift-nio"),
                    .product(name: "NIOWebSocket", package: "swift-nio")
                ]),
        .target(name: "Netbot",
                dependencies: [
                    "MaxMindDB",
                    "NetbotCore",
                    "NetbotHTTP",
                    "NetbotSOCKS",
                    "NetbotSS",
                    "NetbotTrojan",
                    "NetbotVMESS",
                    .product(name: "ArgumentParser", package: "swift-argument-parser"),
                    .product(name: "EraseNilDecoding", package: "swift-erase-nil-decoding"),
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
        .testTarget(name: "NetbotCoreTests",
                    dependencies: [
                        "NetbotCore",
                        .product(name: "NIO", package: "swift-nio")
                    ]),
        .testTarget(name: "NetbotTests",
                    dependencies: [
                        "Netbot",
                        "NetbotCore",
                        "NetbotHTTP",
                        "NetbotSOCKS",
                        "NetbotSS",
                        "NetbotVMESS",
                        .product(name: "NIO", package: "swift-nio"),
                        .product(name: "NIOHTTP1", package: "swift-nio"),
                        .product(name: "NIOSSL", package: "swift-nio-ssl"),
                        .product(name: "NIOExtras", package: "swift-nio-extras"),
                        .product(name: "NIOTransportServices", package: "swift-nio-transport-services")
                    ],
                    exclude: [ "RuleTests.swift.gyb" ]
                   ),
        .testTarget(name: "NetbotTrojanTests",
                    dependencies: [
                        "NetbotTrojan"
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
