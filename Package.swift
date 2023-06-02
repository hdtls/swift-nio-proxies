// swift-tools-version:5.7
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
let swiftNIOCore: Target.Dependency = .product(name: "NIOCore", package: "swift-nio")
let swiftNIOEmbedded: Target.Dependency = .product(name: "NIOEmbedded", package: "swift-nio")
let swiftNIOHTTP1: Target.Dependency = .product(name: "NIOHTTP1", package: "swift-nio")
let swiftNIOPosix: Target.Dependency = .product(name: "NIOPosix", package: "swift-nio")
let swiftNIOSSL: Target.Dependency = .product(name: "NIOSSL", package: "swift-nio-ssl")
let swiftNIOTransportServices: Target.Dependency = .product(
  name: "NIOTransportServices",
  package: "swift-nio-transport-services"
)
let swiftCrypto: Target.Dependency = .product(name: "Crypto", package: "swift-crypto")
let swiftLog: Target.Dependency = .product(name: "Logging", package: "swift-log")
let swiftCertificates: Target.Dependency = .product(name: "X509", package: "swift-certificates")

let package = Package(
  name: "swift-nio-netbot",
  platforms: [
    .macOS(.v10_15),
    .iOS(.v13),
  ],
  products: [
    .library(name: "NECLICore", targets: ["NECLICore"]),
    .library(name: "NECore", targets: ["NECore"]),
    .library(name: "NEDNS", targets: ["NEDNS"]),
    .library(name: "NEHTTP", targets: ["NEHTTP"]),
    .library(name: "NEHTTPMitM", targets: ["NEHTTPMitM"]),
    .library(name: "NEMisc", targets: ["NEMisc"]),
    .library(name: "NEPrettyBytes", targets: ["NEPrettyBytes"]),
    .library(name: "NESHAKE128", targets: ["NESHAKE128"]),
    .library(name: "NESOCKS", targets: ["NESOCKS"]),
    .library(name: "NESS", targets: ["NESS"]),
    .library(name: "NEVMESS", targets: ["NEVMESS"]),
    .executable(name: "netbotcli", targets: ["NECLI"]),
  ],
  dependencies: [
    .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.0.1"),
    .package(url: "https://github.com/apple/swift-crypto.git", from: "2.1.0"),
    .package(url: "https://github.com/apple/swift-log.git", from: "1.4.2"),
    .package(url: "https://github.com/apple/swift-nio.git", from: "2.32.1"),
    .package(url: "https://github.com/apple/swift-nio-ssl.git", from: "2.14.1"),
    .package(url: "https://github.com/apple/swift-nio-extras.git", from: "1.10.0"),
    .package(url: "https://github.com/apple/swift-nio-transport-services.git", from: "1.11.0"),
    .package(url: "https://github.com/apple/swift-format.git", from: "508.0.0"),
    .package(url: "https://github.com/apple/swift-certificates.git", from: "0.2.0"),
    .package(url: "https://github.com/apple/swift-docc-plugin", from: "1.2.0"),
    .package(url: "https://github.com/hdtls/swift-maxminddb.git", from: "1.0.0"),
  ],
  targets: [
    .executableTarget(name: "NECLI", dependencies: ["NECLICore", swiftLog, swiftArgumentParser]),
    .target(name: "CNESHAKE128"),
    .target(
      name: "NECLICore",
      dependencies: ["NECore", swiftLog, .product(name: "MaxMindDB", package: "swift-maxminddb")]
    ),
    .target(
      name: "NECore",
      dependencies: [
        "NEDNS",
        "NEHTTP",
        "NEHTTPMitM",
        "NEMisc",
        "NESOCKS",
        "NESS",
        "NEVMESS",
        swiftCrypto,
        swiftNIOCore,
        swiftNIOPosix,
        swiftLog,
        swiftNIOSSL,
        swiftNIOHTTP1,
        swiftNIOTransportServices,
        .product(name: "NIOConcurrencyHelpers", package: "swift-nio"),
        .product(name: "NIOExtras", package: "swift-nio-extras"),
        .product(name: "NIOHTTPCompression", package: "swift-nio-extras"),
        .product(name: "NIOWebSocket", package: "swift-nio"),
      ]
    ),
    .target(name: "NEDNS", dependencies: [swiftNIOCore, swiftNIOPosix]),
    .target(name: "NEHTTP", dependencies: ["NEMisc", swiftNIOCore, swiftNIOHTTP1]),
    .target(
      name: "NEHTTPMitM",
      dependencies: [swiftNIOCore, swiftNIOHTTP1, swiftNIOSSL, swiftLog, swiftCertificates]
    ),
    .target(name: "NEMisc", dependencies: [swiftNIOCore, swiftNIOPosix]),
    .target(name: "NEPrettyBytes"),
    .target(name: "NESHAKE128", dependencies: ["CNESHAKE128", "NEPrettyBytes", swiftCrypto]),
    .target(name: "NESOCKS", dependencies: ["NEMisc", swiftNIOCore]),
    .target(name: "NESS", dependencies: ["NEMisc", "NEPrettyBytes", swiftCrypto, swiftNIOCore]),
    .target(
      name: "NEVMESS",
      dependencies: ["NEMisc", "NEPrettyBytes", "NESHAKE128", swiftCrypto, swiftNIOCore]
    ),
    .testTarget(
      name: "NECLICoreTests",
      dependencies: [
        "NECLICore",
        swiftNIOCore,
        swiftNIOEmbedded,
      ],
      exclude: ["ParsableRuleTests.g.swift.gyb"]
    ),
    .testTarget(
      name: "NECoreTests",
      dependencies: [
        "NECore",
        "NEHTTP",
        "NEMisc",
        "NESOCKS",
        "NESS",
        "NEVMESS",
        swiftNIOCore,
        swiftNIOEmbedded,
        swiftNIOSSL,
        swiftNIOHTTP1,
        swiftNIOTransportServices,
        .product(name: "NIOWebSocket", package: "swift-nio"),
      ]
    ),
    .testTarget(
      name: "NEHTTPMitMTests",
      dependencies: ["NEHTTPMitM", swiftNIOCore, swiftNIOEmbedded]
    ),
    .testTarget(
      name: "NEHTTPTests",
      dependencies: ["NEHTTP", swiftNIOCore, swiftNIOEmbedded, swiftNIOHTTP1, swiftNIOSSL]
    ),
    .testTarget(name: "NEMiscTests", dependencies: ["NEMisc", swiftNIOCore, swiftNIOEmbedded]),
    .testTarget(name: "NESHAKE128Tests", dependencies: ["NESHAKE128"]),
    .testTarget(name: "NESOCKSTests", dependencies: ["NESOCKS", swiftNIOCore, swiftNIOEmbedded]),
    .testTarget(
      name: "NESSTests",
      dependencies: ["NEPrettyBytes", "NESS", swiftNIOCore, swiftNIOEmbedded],
      exclude: [
        "RequestEncoderTests.g.swift.gyb",
        "ResponseDecoderTests.g.swift.gyb",
      ]
    ),
    .testTarget(
      name: "NEVMESSTests",
      dependencies: ["NEPrettyBytes", "NEVMESS", "NEMisc", swiftNIOCore, swiftNIOEmbedded]
    ),
  ],
  swiftLanguageVersions: [.v5]
)
