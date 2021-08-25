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
                    .product(name: "NIO", package: "swift-nio"),
                    .product(name: "Crypto", package: "swift-crypto"),
                    .target(name: "Helpers")
                ]),
        .target(name: "Netbot",
                dependencies: [
                    .product(name: "NIO", package: "swift-nio"),
                    .product(name: "NIOHTTP1", package: "swift-nio"),
                    .product(name: "NIOSSL", package: "swift-nio-ssl"),
                    .target(name: "HTTP"),
                    .target(name: "SOCKS"),
                    .target(name: "Shadowsocks")
                ]),
        .executableTarget(name: "Linking",
                          dependencies: [
                            .product(name: "NIO", package: "swift-nio"),
                            .product(name: "NIOSSL", package: "swift-nio-ssl"),
                            .product(name: "Logging", package: "swift-log"),
                            .target(name: "Netbot")
                          ]),
        .testTarget(name: "NetbotTests", dependencies: [ .product(name: "NIOEmbedded", package: "swift-nio"), .target(name: "Netbot") ])
    ],
    swiftLanguageVersions: [.v5]
)
