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
        
        LoggingSystem.bootstrap { label in
            var handler = StreamLogHandler.standardOutput(label: label)
            handler.logLevel = configuration.general.logLevel
            return handler
        }
        
        let netbot = Netbot.init(
            configuration: configuration,
            outboundMode: outboundMode,
            enableHTTPCapture: enableHTTPCapture,
            enableMitm: enableMitm
        )
        
        try netbot.run()
    }
}
