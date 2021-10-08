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
import HTTP

public enum OutboundMode: String, CaseIterable, ExpressibleByArgument {
    case direct
    case global
}

public struct NetbotCommand: ParsableCommand {
    
    public static var configuration: CommandConfiguration = .init(
        commandName: "netbot",
        abstract: "",
        discussion: "",
        version: "1.0.0",
        subcommands: [
            ProxyConfigCommand.self,
            BoringSSLCommand.self
        ])
    
    @Option(help: "The SOCKS5 proxy server listen address.")
    var socksListenAddress: String?
    
    @Option(help: "The SOCKS5 proxy server listen port.")
    var socksListenPort: Int?
    
    @Option(help: "The SOCKS5 proxy server listen authority (e.g., 127.0.0.1:10000).")
    var socksListen: String?
    
    @Option(help: "The web and secure web proxy server listen address.")
    var httpListenAddress: String?
    
    @Option(help: "The web and secure web proxy server listen port.")
    var httpListenPort: Int?
    
    @Option(help: "The web and secure web proxy server listen authority. (e.g., 127.0.0.1:10000)")
    var httpListen: String?
    
    @Option(name: .shortAndLong, help: "The proxy configuration file.")
    public var configFilePath: String?
    
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
        
        if let config = configFilePath {
            let data = try Data(contentsOf: URL(fileURLWithPath: config))
            let jsonObject = Parser.jsonObject(with: data)
            let jsonData = try JSONSerialization.data(withJSONObject: jsonObject, options: .fragmentsAllowed)
            configuration = try JSONDecoder().decode(Configuration.self, from: jsonData)
        }
        
        var proxyctl: [String] = []
        
        if let socksListenAddress = socksListenAddress {
            proxyctl.append("--socks-listen-address")
            proxyctl.append(socksListenAddress)
            configuration.generalField.socksListenAddress = socksListenAddress
        }
        
        if let socksListenPort = socksListenPort {
            proxyctl.append("--socks-listen-port")
            proxyctl.append("\(socksListenPort)")
            configuration.generalField.socksListenPort = socksListenPort
        }
        
        if let httpListenAddress = httpListenAddress {
            proxyctl.append("--http-listen-address")
            proxyctl.append("\(httpListenAddress)")
            configuration.generalField.httpListenAddress = httpListenAddress
        }
        
        if let httpListenPort = httpListenPort {
            proxyctl.append("--http-listen-port")
            proxyctl.append("\(httpListenPort)")
            configuration.generalField.httpListenPort = httpListenPort
        }

        if !proxyctl.isEmpty {
            proxyctl.insert("install", at: 0)
        }
        //        ProxyConfigCommand.main(proxyctl)
        
        if let reqMsgFilter = reqMsgFilter {
            configuration.replicaField.reqMsgFilter = reqMsgFilter
        }
        
        let netbot = Netbot.init(
            configuration: configuration,
            outboundMode: outboundMode,
            basicAuthorization: .none,
            enableHTTPCapture: enableHTTPCapture,
            enableMitm: enableMitm
        )

        try netbot.run()
    }
}
