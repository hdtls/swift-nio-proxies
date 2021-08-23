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
        .library(name: "Netbot", targets: ["Netbot"]),
        .library(name: "NWHTTPProxy", targets: ["NWHTTPProxy"]),
        .library(name: "NWSOCKSProxy", targets: ["NWSOCKSProxy"]),
        .library(name: "NWSSProxy", targets: ["NWSSProxy"]),
//        .library(name: "NWSecurity", targets: ["NWSecurity"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.32.1"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "1.1.6"),
    ],
    targets: [
//        .target(name: "NWSecurity",
//                dependencies: [
//                    .product(name: "Crypto", package: "swift-crypto"),
//                    .target(name: "CNWLibmbedcrypto"),
//                    .target(name: "CNWLibsodiumcrypto"),
//                    .target(name: "CNWLibsscrypto")
//                ]),
        .target(name: "NWHTTPProxy",
                dependencies: [
                    .product(name: "NIO", package: "swift-nio"),
                    .product(name: "NIOHTTP1", package: "swift-nio"),
                    .product(name: "NIOPosix", package: "swift-nio"),
                    .product(name: "NIOCore", package: "swift-nio"),
                    .product(name: "NIOConcurrencyHelpers", package: "swift-nio"),
                ]),
        .target(name: "NWSOCKSProxy",
                dependencies: [
                    .product(name: "NIO", package: "swift-nio")
                ]),
        .target(name: "NWSSProxy",
                dependencies: [
                    .product(name: "NIO", package: "swift-nio"),
                    .product(name: "Crypto", package: "swift-crypto"),
//                    .target(name: "NWSecurity"),
                    .target(name: "NWSOCKSProxy")
                ]),
        .target(name: "Netbot",
                dependencies: [
                    .product(name: "NIO", package: "swift-nio"),
                    .product(name: "NIOHTTP1", package: "swift-nio"),
                    .target(name: "NWHTTPProxy"),
                    .target(name: "NWSOCKSProxy"),
                    .target(name: "NWSSProxy")
                ]),
        .executableTarget(name: "NetbotClient", dependencies: [ .target(name: "Netbot") ]),
        .testTarget(name: "NetbotTests", dependencies: [ .target(name: "Netbot") ]),
//        .testTarget(name: "CNWLibsscryptoTests", dependencies: [ .target(name: "CNWLibsscrypto") ]),
        .testTarget(name: "NWHTTPProxyTests", dependencies: [ .target(name: "NWHTTPProxy") ]),
        .testTarget(name: "NWSecurityTests",
                    dependencies: [
//                        .target(name: "NWSecurity"),
                        .product(name: "Crypto", package: "swift-crypto")
                    ]),
        .testTarget(name: "NWSSProxyTests", dependencies: [ .target(name: "NWSSProxy") ])
    ],
    swiftLanguageVersions: [.v5]
)
