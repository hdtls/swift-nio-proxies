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
import Logging
import NIONetbot

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

@main
public struct NetbotCLITool: AsyncParsableCommand {

    #if os(macOS)
    /// A configuration object use for config this command.
    public static var configuration: CommandConfiguration = .init(
        commandName: "netbotcli",
        abstract: "",
        discussion: "",
        version: "1.0.0",
        subcommands: [
            SystemProxyConfigCommand.self
        ]
    )
    #else
    /// A configuration object use for config this command.
    public static var configuration: CommandConfiguration = .init(
        commandName: "netbotcli",
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

    /// The log level for logger.
    ///
    /// Has higher priority than the loglevel defined in the profile file.
    @Option(help: "The log level for logger.")
    public var logLevel: Logger.Level?

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
        // Downloading external resources...
        let supportDirectory: URL = {
            let url = FileManager.default.urls(
                for: .applicationSupportDirectory,
                in: .userDomainMask
            )[0]
            return url.appendingPathComponent("io.tenbits.Netbot")
        }()

        // Default GeoLite2 database file url.
        let maxminddbURL = supportDirectory.appendingPathComponent("GeoLite2-Country.mmdb")

        let externalResourcesDirectory = supportDirectory.appendingPathComponent(
            "External Resources"
        )

        try FileManager.default.createDirectory(
            at: externalResourcesDirectory,
            withIntermediateDirectories: true
        )

        var profile: Profile = try await loadProfile()

        let logLevel = logLevel ?? profile.general.logLevel

        LoggingSystem.bootstrap { label in
            var handler = StreamLogHandler.standardOutput(label: label)
            handler.logLevel = logLevel
            return handler
        }

        let logger = Logger(label: "io.tenbits.Netbot")

        // Perform GeoLite2-Country.mmdb downloading...
        if !FileManager.default.fileExists(atPath: maxminddbURL.path) {
            logger.trace("Downloading GeoLite2-Country.mmdb")
            logger.trace("Downloading from https://git.io/GeoLite2-Country.mmdb")
            let (url, _) = try await URLSession(configuration: .ephemeral).download(
                from: URL(string: "https://git.io/GeoLite2-Country.mmdb")!
            )

            try FileManager.default.moveItem(at: url, to: maxminddbURL)
        }

        let filtered = profile.rules.filter({ $0 is ExternalRuleResources })
        if filtered.isEmpty {
            do {
                // Perform proxy rule external resources downloading...
                logger.trace("Downloading external resources")
                for e in filtered {
                    let resources = e as! ParsableRule & ExternalRuleResources
                    let externalResourcesURL = try resources.externalResourcesURL

                    logger.trace("Downloading from \(externalResourcesURL)")
                    let (srcURL, _) = try await URLSession(configuration: .ephemeral).download(
                        from: externalResourcesURL
                    )

                    // Remove older file first if exists.
                    let resourcesURL = externalResourcesDirectory.appendingPathComponent(
                        resources.externalResourcesStorageName
                    )
                    if FileManager.default.fileExists(atPath: resourcesURL.path) {
                        try FileManager.default.removeItem(at: resourcesURL)
                    }
                    try FileManager.default.moveItem(at: srcURL, to: resourcesURL)
                }
            } catch {}
        }

        // Reload profile after resources files downloaded.
        profile = try await loadProfile()

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

            //            SystemProxyConfigCommand.main(proxyctl)
        }
        #endif

        try await App.init(
            profile: profile,
            outboundMode: outboundMode,
            enableHTTPCapture: enableHTTPCapture,
            enableMitm: enableMitm,
            maxMindDB: .init(file: maxminddbURL.path)
        )
        .run()
    }

    func loadProfile() async throws -> Profile {
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

        let externalResourcesDirectory: URL = {
            var url = FileManager.default.urls(
                for: .applicationSupportDirectory,
                in: .userDomainMask
            )[0]
            url.appendPathComponent("io.tenbits.Netbot")
            return url.appendingPathComponent("External Resources")
        }()

        let rules = profile.rules.map {
            guard var resources = $0 as? ExternalRuleResources & ParsableRule else {
                return $0
            }

            resources.loadAllRules(
                from: externalResourcesDirectory.appendingPathComponent(
                    resources.externalResourcesStorageName
                )
            )
            return resources
        }
        profile.rules = rules

        return profile
    }
}
