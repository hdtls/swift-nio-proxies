// swift-tools-version: 5.9
//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright 2021 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import PackageDescription

let swiftNIOCore: Target.Dependency = .product(name: "NIOCore", package: "swift-nio")
let swiftNIOEmbedded: Target.Dependency = .product(name: "NIOEmbedded", package: "swift-nio")
let swiftNIOHTTP1: Target.Dependency = .product(name: "NIOHTTP1", package: "swift-nio")
let swiftCrypto: Target.Dependency = .product(name: "Crypto", package: "swift-crypto")

let package = Package(
  name: "swift-nio-proxies",
  platforms: [
    .macOS(.v10_15),
    .iOS(.v13),
    .watchOS(.v6),
    .tvOS(.v13),
  ],
  products: [
    .library(name: "NEAddressProcessing", targets: ["NEAddressProcessing"]),
    .library(name: "NEPrettyBytes", targets: ["NEPrettyBytes"]),
    .library(name: "NEHTTP", targets: ["NEHTTP"]),
    .library(name: "NESOCKS", targets: ["NESOCKS"]),
    .library(name: "NESS", targets: ["NESS"]),
    .library(name: "NEVMESS", targets: ["NEVMESS"]),
  ],
  dependencies: [
    .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    .package(url: "https://github.com/apple/swift-nio.git", from: "2.32.1"),
    .package(url: "https://github.com/apple/swift-http-types.git", from: "1.3.0"),
    .package(url: "https://github.com/apple/swift-nio-extras.git", from: "1.24.1"),
  ],
  targets: [
    .target(name: "NEAddressProcessing"),
    .target(name: "CNESHAKE128"),
    .target(
      name: "NEHTTP",
      dependencies: [
        "NEAddressProcessing", swiftNIOCore, swiftNIOHTTP1,
        .product(name: "HTTPTypes", package: "swift-http-types"),
        .product(name: "NIOHTTPTypesHTTP1", package: "swift-nio-extras"),
      ]
    ),
    .target(name: "NEPrettyBytes"),
    .target(name: "NESHAKE128", dependencies: ["CNESHAKE128", "NEPrettyBytes", swiftCrypto]),
    .target(name: "NESOCKS", dependencies: ["NEAddressProcessing", swiftNIOCore]),
    .target(
      name: "NESS",
      dependencies: ["NEAddressProcessing", "NEPrettyBytes", swiftCrypto, swiftNIOCore]
    ),
    .target(
      name: "NEVMESS",
      dependencies: [
        "NEAddressProcessing",
        "NEPrettyBytes",
        "NESHAKE128",
        swiftCrypto,
        swiftNIOCore,
      ]
    ),
    .testTarget(
      name: "NEHTTPTests",
      dependencies: [
        "NEHTTP", swiftNIOCore, swiftNIOEmbedded, swiftNIOHTTP1,
        .product(name: "NIOHTTPTypesHTTP1", package: "swift-nio-extras"),
      ]
    ),
    .testTarget(name: "NEAddressProcessingTests", dependencies: ["NEAddressProcessing"]),
    .testTarget(name: "NESHAKE128Tests", dependencies: ["NESHAKE128"]),
    .testTarget(name: "NESOCKSTests", dependencies: ["NESOCKS", swiftNIOCore, swiftNIOEmbedded]),
    .testTarget(
      name: "NESSTests",
      dependencies: ["NEPrettyBytes", "NESS", swiftNIOCore, swiftNIOEmbedded]
    ),
    .testTarget(
      name: "NEVMESSTests",
      dependencies: [
        "NEPrettyBytes", "NEVMESS", "NEAddressProcessing", swiftCrypto, swiftNIOCore,
        swiftNIOEmbedded,
      ]
    ),
  ],
  swiftLanguageVersions: [.v5]
)
