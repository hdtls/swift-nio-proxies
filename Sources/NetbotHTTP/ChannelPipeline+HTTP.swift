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
import NetbotCore
import NIOCore
import NIOHTTP1
import NIOSSL
import NIOTLS
import NIOHTTPCompression

extension ChannelPipeline {
    
    public func addHTTPProxyClientHandlers(position: ChannelPipeline.Position = .last,
                                           logger: Logger,
                                           credential: Credential? = nil,
                                           taskAddress: NetAddress) -> EventLoopFuture<Void> {
        let eventLoopFuture: EventLoopFuture<Void>
        
        if eventLoop.inEventLoop {
            let result = Result<Void, Error> {
                try self.syncOperations.addHTTPProxyClientHandlers(position: position, logger: logger, credential: credential, taskAddress: taskAddress)
            }
            eventLoopFuture = eventLoop.makeCompletedFuture(result)
        } else {
            eventLoopFuture = eventLoop.submit {
                try self.syncOperations.addHTTPProxyClientHandlers(position: position, logger: logger, credential: credential, taskAddress: taskAddress)
            }
        }
        
        return eventLoopFuture
    }
    
    public func configureHTTPProxyServerHandlers(position: ChannelPipeline.Position = .last,
                                                 logger: Logger,
                                                 credential: Credential? = nil,
                                                 enableHTTPCapture: Bool = false,
                                                 enableMitM: Bool = false,
                                                 mitmConfig: MitMConfiguration? = nil,
                                                 completion: @escaping (Request) -> EventLoopFuture<Channel>) -> EventLoopFuture<Void> {
        let eventLoopFuture: EventLoopFuture<Void>
        
        let execution = {
            try self.syncOperations.configureHTTPProxyServerHandlers(position: position,
                                                                     logger: logger,
                                                                     credential: credential,
                                                                     enableHTTPCapture: enableHTTPCapture,
                                                                     enableMitM: enableMitM,
                                                                     mitmConfig: mitmConfig,
                                                                     completion: completion)
        }
        
        if eventLoop.inEventLoop {
            eventLoopFuture = eventLoop.makeCompletedFuture(.init(catching: execution))
        } else {
            eventLoopFuture = eventLoop.submit(execution)
        }
        
        return eventLoopFuture
    }
}

extension ChannelPipeline.SynchronousOperations {
    
    public func addHTTPProxyClientHandlers(position: ChannelPipeline.Position = .last,
                                           logger: Logger,
                                           credential: Credential? = nil,
                                           taskAddress: NetAddress) throws {
        eventLoop.assertInEventLoop()
        let handlers: [ChannelHandler] = [HTTP1ClientCONNECTTunnelHandler(logger: logger, credential: credential, taskAddress: taskAddress)]
        try self.addHTTPClientHandlers()
        try self.addHandlers(handlers, position: position)
    }
    
    public func configureHTTPProxyServerHandlers(position: ChannelPipeline.Position = .last,
                                                 logger: Logger,
                                                 credential: Credential? = nil,
                                                 enableHTTPCapture: Bool = false,
                                                 enableMitM: Bool = false,
                                                 mitmConfig: MitMConfiguration? = nil,
                                                 completion: @escaping (Request) -> EventLoopFuture<Channel>) throws {
        self.eventLoop.assertInEventLoop()
        
        let responseEncoder = HTTPResponseEncoder()
        let requestDecoder = HTTPRequestDecoder(leftOverBytesStrategy: .forwardBytes)
        
        let serverHandler = HTTPProxyServerHandler(logger: logger, authorization: credential != nil ? .init(username: credential!.identity, password: credential!.identityTokenString) : nil, outEFLBuilder: completion) { req, channel in
            let serverHostname = req.serverHostname
            
            let enableHTTPCapture0 = {
                // Those handlers will be added to `self` to enable HTTP capture for request.
                let handlers0: [ChannelHandler] = [
                    HTTPResponseCompressor(),
                    HTTPCaptureHandler<HTTPRequestHead>(logger: logger),
                    HTTPIOTransformer<HTTPRequestHead>()
                ]
                
                // Those handlers will be added to the channel to enable HTTP capture for response.
                let handlers1: [ChannelHandler] = [
                    NIOHTTPResponseDecompressor(limit: .none),
                    HTTPCaptureHandler<HTTPResponseHead>(logger: logger),
                    HTTPIOTransformer<HTTPResponseHead>()
                ]
                
                try self.addHandlers(handlers0)
                
                try channel.pipeline.syncOperations.addHandlers(handlers1)
            }
            
            guard req.httpMethod == .CONNECT else {
                try enableHTTPCapture0()
                return
            }
            
            guard enableMitM else {
                return
            }
            
            guard let mitmConfig = mitmConfig else {
                // In order to enable the HTTP MitM feature, you must provide the corresponding configuration.
                throw NIOSSLError.failedToLoadCertificate
            }
            
            // Filter p12 bundle from pool
            let p12 = mitmConfig.pool.first {
                guard $0.key.hasPrefix("*") else {
                    return $0.key == serverHostname
                }
                return serverHostname.contains($0.key.dropFirst())
            }?.value
            
            guard let p12 = p12 else {
                return
            }
            
            let certificateChain = p12.certificateChain.map(NIOSSLCertificateSource.certificate)
            let privateKey = NIOSSLPrivateKeySource.privateKey(p12.privateKey)
            
            try self.configureSSLServerHandlers(certificateChain: certificateChain, privateKey: privateKey)
            try self.configureHTTPServerPipeline(withPipeliningAssistance: false, withErrorHandling: false)
            
            // Peer channel pipeline setup.
            try channel.pipeline.syncOperations.addSSLClientHandlers(serverHostname: serverHostname)
            try channel.pipeline.syncOperations.addHTTPClientHandlers()
            
            try enableHTTPCapture0()
        }
        
        let handlers: [RemovableChannelHandler] = [responseEncoder, ByteToMessageHandler(requestDecoder), serverHandler]
        
        try self.addHandlers(handlers, position: position)
    }
}
