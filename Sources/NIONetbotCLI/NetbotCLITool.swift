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
public struct NetbotCLITool: ParsableCommand {

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

    public func run() throws {
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
            let g = DispatchGroup.init()
            g.enter()

            print("Downloading https://git.io/GeoLite2-Country.mmdb")
            let totalSize: Double = 60
            var prettyPrint = String.init(repeating: "-", count: Int(totalSize))
            print("\r[\(prettyPrint)] 0%", terminator: "")
            fflush(stdout)

            let task = URLSession(configuration: .ephemeral).downloadTask(
                with: URL(string: "https://git.io/GeoLite2-Country.mmdb")!
            ) { url, response, error in
                defer {
                    g.leave()
                }
                guard let url = url, error == nil else {
                    return
                }

                do {
                    let supportDirectory = dstURL.deletingLastPathComponent()
                    try FileManager.default.createDirectory(
                        at: supportDirectory,
                        withIntermediateDirectories: true
                    )
                    try FileManager.default.moveItem(at: url, to: dstURL)
                } catch {
                    assertionFailure(error.localizedDescription)
                }
            }

            task.resume()

            #if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
            let observation = task.progress.observe(\.fractionCompleted, options: .new) {
                progress,
                _ in
                let range = Range.init(
                    .init(location: 0, length: Int(progress.fractionCompleted * totalSize)),
                    in: prettyPrint
                )
                prettyPrint = prettyPrint.replacingOccurrences(of: "-", with: "#", range: range)

                print(
                    "\r[\(prettyPrint)] \(Int(progress.fractionCompleted * 100))%",
                    terminator: progress.fractionCompleted < 1 ? "" : "\n"
                )
                fflush(__stdoutp)
            }
            #endif

            // Wait downloading done.
            g.wait()

            #if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
            observation.invalidate()
            #endif
        }

        let netbot = App.init(
            profile: profile,
            outboundMode: outboundMode,
            enableHTTPCapture: enableHTTPCapture,
            enableMitm: enableMitm,
            geoLite2: try .init(file: dstURL.path)
        )

        try netbot.run()
    }
}