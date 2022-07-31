//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2021 Junfeng Zhang. and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import ArgumentParser
import Foundation
import NIONetbot

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

@main
public struct NetbotCLITool: AsyncParsableCommand {

    #if os(macOS)
    /// A configuration object use for config this command.
    public static var configuration: CommandConfiguration = .init(
        commandName: "netbot",
        abstract: "",
        discussion: "",
        version: "1.0.0",
        subcommands: [
            ProxyConfigCommand.self
        ]
    )
    #else
    /// A configuration object use for config this command.
    public static var configuration: CommandConfiguration = .init(
        commandName: "netbot",
        abstract: "",
        discussion: "",
        version: "1.0.0"
    )
    #endif

    /// The SOCKS5 proxy server listen address.
    @Option(help: "The SOCKS5 proxy server listen address.")
    public var socksListenAddress: String?

    /// The SOCKS5 proxy server listen port.
    @Option(help: "The SOCKS5 proxy server listen port.")
    public var socksListenPort: Int?

    /// The web and secure web proxy server listen address.
    @Option(help: "The web and secure web proxy server listen address.")
    public var httpListenAddress: String?

    /// The web and secure web proxy server listen port.
    @Option(help: "The web and secure web proxy server listen port.")
    public var httpListenPort: Int?

    /// The proxy configuration file path.
    @Option(name: .shortAndLong, help: "The proxy profile file.")
    public var profileFile: String?

    /// The proxy outbound mode.
    @Option(help: "The proxy outbound mode.")
    public var outboundMode: OutboundMode = .direct

    /// A boolean value that determines whether http capture should be enabled.
    @Flag(help: "Enable HTTP capture, should be enabled only when needed.")
    public var enableHTTPCapture: Bool = false

    /// A boolean value that determines whether MitM should be enabled.
    @Flag(help: "Enable MitM, should be enabled only when needed.")
    public var enableMitm: Bool = false

    /// Initialize an instance of `NetbotCLITool`.
    public init() {}

    public func run() async throws {
        var profile: Profile = .init()

        if let path = profileFile {
            let data = try Data(contentsOf: URL(fileURLWithPath: path))
            let jsonObject = try ProfileSerialization.jsonObject(with: data)
            let jsonData = try JSONSerialization.data(
                withJSONObject: jsonObject,
                options: .fragmentsAllowed
            )
            let jsonDecoder = JSONDecoder()
            jsonDecoder.keyDecodingStrategy = .convertFromSnakeCase
            profile = try jsonDecoder.decode(Profile.self, from: jsonData)
        }

        #if canImport(SystemConfiguration)
        var proxyctl: [String] = []

        profile.general.socksListenAddress =
            socksListenAddress ?? profile.general.socksListenAddress
        if let socksListenAddress = profile.general.socksListenAddress {
            proxyctl.append("--socks-listen-address")
            proxyctl.append(socksListenAddress)
        }

        profile.general.socksListenPort =
            socksListenPort ?? profile.general.socksListenPort
        if let socksListenPort = profile.general.socksListenPort {
            proxyctl.append("--socks-listen-port")
            proxyctl.append("\(socksListenPort)")
        }

        profile.general.httpListenAddress =
            httpListenAddress ?? profile.general.httpListenAddress
        if let httpListenAddress = profile.general.httpListenAddress {
            proxyctl.append("--http-listen-address")
            proxyctl.append("\(httpListenAddress)")
        }

        profile.general.httpListenPort =
            httpListenPort ?? profile.general.httpListenPort
        if let httpListenPort = profile.general.httpListenPort {
            proxyctl.append("--http-listen-port")
            proxyctl.append("\(httpListenPort)")
        }

        if profile.general.excludeSimpleHostnames {
            proxyctl.append("--exclude-simple-hostnames")
        }

        if !profile.general.exceptions.isEmpty {
            proxyctl.append("--exceptions")
            proxyctl.append(profile.general.exceptions.joined(separator: ","))
        }

        if !proxyctl.isEmpty {
            proxyctl.insert("install", at: 0)

            //            ProxyConfigCommand.main(proxyctl)
        }
        #endif

        /// Default GeoLite2 database file url.
        let dstURL: URL = {
            var dstURL = FileManager.default.urls(
                for: .applicationSupportDirectory,
                in: .userDomainMask
            )[0]
            dstURL.appendPathComponent("io.tenbits.Netbot")
            dstURL.appendPathComponent("GeoLite2-Country.mmdb")
            return dstURL
        }()

        if !FileManager.default.fileExists(atPath: dstURL.path) {
            let _: Void = try await withCheckedThrowingContinuation { continuation in
                URLSession(configuration: .ephemeral).downloadTask(
                    with: URL(string: "https://git.io/GeoLite2-Country.mmdb")!
                ) { url, response, error in
                    guard let url = url, error == nil else {
                        continuation.resume(throwing: error!)
                        return
                    }

                    do {
                        let supportDirectory = dstURL.deletingLastPathComponent()
                        try FileManager.default.createDirectory(
                            at: supportDirectory,
                            withIntermediateDirectories: true
                        )
                        try FileManager.default.moveItem(at: url, to: dstURL)
                        continuation.resume()
                    } catch {
                        assertionFailure(error.localizedDescription)
                        continuation.resume(throwing: error)
                    }
                }
                .resume()
            }
        }

        try await App.init(
            profile: profile,
            outboundMode: outboundMode,
            enableHTTPCapture: enableHTTPCapture,
            enableMitm: enableMitm,
            maxMindDB: .init(file: dstURL.path)
        )
        .run()
    }
}
