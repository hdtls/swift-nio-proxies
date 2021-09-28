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

import NIOCore
import NIOSSL
import Helpers

public enum ProxyProtocol: String, Codable {
    case ss
    case http
    case socks5
    case direct
}

public struct ProxyProfile {
    
    /// Name for proxy.
    public var name: String
    
    /// Proxy protocl.
    public var `protocol`: ProxyProtocol
    
    /// Connect user.
    public var user: String
    
    /// Connect user token.
    public var token: String
    
    /// Address the server will connect to.
    public var address: String
    
    /// Port the server will connect to.
    public var port: Int
    
    /// Listen backlog.
    public var backlog: Int
    
    /// When `true`, can prevent errors re-binding to a socket after successive server restarts.
    public var reuseAddress: Bool
    
    /// When `true`, OS will attempt to minimize TCP packet delay.
    public var tcpNoDelay: Bool
    
    /// When `true`, HTTP server will support pipelined requests.
    public var supportPipelining: Bool
    
    public var tlsConfiguration: TLSConfiguration?
    
    /// A time limit to complete a graceful shutdown
    public var shutdownTimeout: TimeAmount
    
    public init(name: String,
                protocol: ProxyProtocol,
                user: String,
                token: String,
                address: String,
                port: Int,
                backlog: Int = 256,
                reuseAddress: Bool = true,
                tcpNoDelay: Bool = true,
                supportPipelining: Bool = true,
                tlsConfiguration: TLSConfiguration? = nil,
                shutdownTimeout: TimeAmount = .seconds(10)) {
        
        self.name = name
        self.protocol = `protocol`
        self.user = user
        self.token = token
        self.address = address
        self.port = port
        self.backlog = backlog
        self.reuseAddress = reuseAddress
        self.tcpNoDelay = tcpNoDelay
        self.supportPipelining = supportPipelining
        self.tlsConfiguration = tlsConfiguration
        self.shutdownTimeout = shutdownTimeout
    }
}
