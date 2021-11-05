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
import HTTP

extension OutboundMode: ExpressibleByArgument {}

public struct NetbotCommand: ParsableCommand {
    
#if canImport(SystemConfiguration)
    public static var configuration: CommandConfiguration = .init(
        commandName: "netbot",
        abstract: "",
        discussion: "",
        version: "1.0.0",
        subcommands: [
            ProxyConfigCommand.self,
            BoringSSLCommand.self
        ])
#else
    public static var configuration: CommandConfiguration = .init(
        commandName: "netbot",
        abstract: "",
        discussion: "",
        version: "1.0.0",
        subcommands: [
            BoringSSLCommand.self
        ])
#endif
    
    @Option(help: "The SOCKS5 proxy server listen address.")
    public var socksListenAddress: String?
    
    @Option(help: "The SOCKS5 proxy server listen port.")
    public var socksListenPort: Int?
    
    @Option(help: "The web and secure web proxy server listen address.")
    public var httpListenAddress: String?
    
    @Option(help: "The web and secure web proxy server listen port.")
    public var httpListenPort: Int?
    
    @Option(name: .shortAndLong, help: "The proxy configuration file.")
    public var configFile: String?
    
    @Option(help: "The proxy outbound mode.")
    public var outboundMode: OutboundMode = .direct
    
    @Option(help: "The request message filter, separated by commas.")
    public var reqMsgFilter: String?
    
    @Flag(help: "Enable HTTP capture, should be enabled only when needed.")
    public var enableHTTPCapture: Bool = false
    
    @Flag(help: "Enable MitM, should be enabled only when needed.")
    public var enableMitm: Bool = false
    
    public init() {}
    
    public func run() throws {
        var configuration: Configuration = .init()
        
        if let config = configFile {
            let data = try Data(contentsOf: URL(fileURLWithPath: config))
            let jsonObject = try Parser.jsonObject(with: data)
            let jsonData = try JSONSerialization.data(withJSONObject: jsonObject, options: .fragmentsAllowed)
            configuration = try JSONDecoder().decode(Configuration.self, from: jsonData)
        }
        
#if canImport(SystemConfiguration)
        var proxyctl: [String] = []
        
        configuration.general.socksListenAddress = socksListenAddress ?? configuration.general.socksListenAddress
        if let socksListenAddress = configuration.general.socksListenAddress {
            proxyctl.append("--socks-listen-address")
            proxyctl.append(socksListenAddress)
        }
        
        configuration.general.socksListenPort = socksListenPort ?? configuration.general.socksListenPort
        if let socksListenPort = configuration.general.socksListenPort {
            proxyctl.append("--socks-listen-port")
            proxyctl.append("\(socksListenPort)")
        }
        
        configuration.general.httpListenAddress = httpListenAddress ?? configuration.general.httpListenAddress
        if let httpListenAddress = configuration.general.httpListenAddress {
            proxyctl.append("--http-listen-address")
            proxyctl.append("\(httpListenAddress)")
        }
        
        configuration.general.httpListenPort = httpListenPort ?? configuration.general.httpListenPort
        if let httpListenPort = configuration.general.httpListenPort {
            proxyctl.append("--http-listen-port")
            proxyctl.append("\(httpListenPort)")
        }
        
        if configuration.general.excludeSimpleHostnames {
            proxyctl.append("--exclude-simple-hostnames")
        }
        
        if let exceptions = configuration.general.exceptions {
            proxyctl.append("--exceptions")
            proxyctl.append(exceptions.joined(separator: ","))
        }
        
        if !proxyctl.isEmpty {
            proxyctl.insert("install", at: 0)
            
            //            ProxyConfigCommand.main(proxyctl)
        }
#endif
        
        if let reqMsgFilter = reqMsgFilter {
            configuration.replica.reqMsgFilter = reqMsgFilter
        }
        
        /// Default GeoLite2 database file url.
        let dstURL: URL = {
            var dstURL = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            dstURL.appendPathComponent("io.tenbits.Netbot")
            dstURL.appendPathComponent("GeoLite2-Country.mmdb")
            return dstURL
        }()
        
        if FileManager.default.fileExists(atPath: dstURL.path) {
            let g = DispatchGroup.init()
            g.enter()
            
            print("Downloading https://git.io/GeoLite2-Country.mmdb")
            let totalSize: Double = 60
            var prettyPrint = String.init(repeating: "-", count: Int(totalSize))
            print("\r[\(prettyPrint)] 0%", terminator: "")
            fflush(__stdoutp)
            
            let task = URLSession(configuration: .ephemeral).downloadTask(with: URL(string: "https://git.io/GeoLite2-Country.mmdb")!) { url, response, error in
                defer {
                    g.leave()
                }
                guard let url = url, error == nil else {
                    return
                }
                do {
                    let supportDirectory = dstURL.deletingLastPathComponent()
                    try FileManager.default.createDirectory(at: supportDirectory, withIntermediateDirectories: true)
                    try FileManager.default.moveItem(at: url, to: dstURL)
                } catch {
                    assertionFailure(error.localizedDescription)
                }
            }
            
            task.resume()
            
            let observation = task.progress.observe(\.fractionCompleted, options: .new) { progress, _ in
                let range = Range.init(.init(location: 0, length: Int(progress.fractionCompleted * totalSize)), in: prettyPrint)
                prettyPrint = prettyPrint.replacingOccurrences(of: "-", with: "#", range: range)
                
                print("\r[\(prettyPrint)] \(Int(progress.fractionCompleted * 100))%", terminator: progress.fractionCompleted < 1 ? "" : "\n")
                fflush(__stdoutp)
            }
            
            // Wait downloading done.
            g.wait()
            observation.invalidate()
        }
        
        let netbot = Netbot.init(
            configuration: configuration,
            outboundMode: outboundMode,
            enableHTTPCapture: enableHTTPCapture,
            enableMitm: enableMitm,
            geoLite2: try .init(file: dstURL.path)
        )
        
        try netbot.run()
    }
}
