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

import Logging
import NIOCore

extension ChannelPipeline {
    
    public func addHTTPProxyClientHandlers(logger: Logger = .init(label: "com.netbot.http-client-tunnel"),
                                           credential: Credential? = nil,
                                           position: Position = .last) -> EventLoopFuture<Void> {
        let eventLoopFuture: EventLoopFuture<Void>
        
        if eventLoop.inEventLoop {
            let result = Result<Void, Error> {
                try syncOperations.addHTTPProxyClientHandlers(logger: logger, credential: credential, position: position)
            }
            eventLoopFuture = eventLoop.makeCompletedFuture(result)
        } else {
            eventLoopFuture = eventLoop.submit({
                try self.syncOperations.addHTTPProxyClientHandlers(logger: logger, credential: credential, position: position)
            })
        }
        
        return eventLoopFuture
    }
    
    public func configureHTTPProxyServerHandlers(logger: Logger = .init(label: "com.netbot.http-server-tunnel"),
                                                 credential: Credential? = nil,
                                                 position: ChannelPipeline.Position = .last,
                                                 proxyProtocol: ProxyProtocol,
                                                 completion: @escaping (String) -> EventLoopFuture<Channel>) -> EventLoopFuture<Void> {
        let eventLoopFuture: EventLoopFuture<Void>
        
        if eventLoop.inEventLoop {
            let result = Result<Void, Error> {
                try syncOperations.configureHTTPProxyServerHandlers(logger: logger, credential: credential, position: position, proxyProtocol: proxyProtocol, completion: completion)
            }
            eventLoopFuture = eventLoop.makeCompletedFuture(result)
        } else {
            eventLoopFuture = eventLoop.submit({
                try self.syncOperations.configureHTTPProxyServerHandlers(logger: logger, credential: credential, position: position, proxyProtocol: proxyProtocol, completion: completion)
            })
        }
        
        return eventLoopFuture
    }
}

public enum ProxyProtocol {
    case http
    case socks
    case shadowsocks
}

extension ChannelPipeline.SynchronousOperations {
    
    public func addHTTPProxyClientHandlers(logger: Logger = .init(label: "com.netbot.http-client-tunnel"),
                                           credential: Credential? = nil,
                                           position: ChannelPipeline.Position = .last) throws {
        eventLoop.assertInEventLoop()
        let handlers: [ChannelHandler] = []
        try addHandlers(handlers, position: position)
    }
    
    public func configureHTTPProxyServerHandlers(logger: Logger = .init(label: "com.netbot.http-server-tunnel"),
                                                 credential: Credential? = nil,
                                                 position: ChannelPipeline.Position = .last,
                                                 proxyProtocol: ProxyProtocol,
                                                 completion: @escaping (String) -> EventLoopFuture<Channel>) throws {
        eventLoop.assertInEventLoop()
    }
}
