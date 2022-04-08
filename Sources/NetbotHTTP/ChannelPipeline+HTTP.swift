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
    
    public func addHTTPProxyClientHandlers(logger: Logger,
                                           taskAddress: NetAddress,
                                           authorization: BasicAuthorization? = nil,
                                           position: ChannelPipeline.Position = .last) -> EventLoopFuture<Void> {
        let execute = {
            try self.syncOperations.addHTTPProxyClientHandlers(
                logger: logger,
                taskAddress: taskAddress,
                authorization: authorization,
                position: position
            )
        }
        
        return self.eventLoop.inEventLoop
        ? self.eventLoop.makeCompletedFuture(.init(catching: execute))
        : self.eventLoop.submit(execute)
    }
    
    public func configureHTTPProxyServerPipeline(logger: Logger,
                                                 authorization: BasicAuthorization? = nil,
                                                 enableHTTPCapture: Bool = false,
                                                 enableMitM: Bool = false,
                                                 mitmConfig: MitMConfiguration? = nil,
                                                 position: ChannelPipeline.Position = .last,
                                                 completion: @escaping (Request) -> EventLoopFuture<Channel>) -> EventLoopFuture<Void> {
        let execute = {
            try self.syncOperations.configureHTTPProxyServerPipeline(
                logger: logger,
                authorization: authorization,
                enableHTTPCapture: enableHTTPCapture,
                enableMitM: enableMitM,
                mitmConfig: mitmConfig,
                position: position,
                completion: completion
            )
        }
        
        return self.eventLoop.inEventLoop
        ? self.eventLoop.makeCompletedFuture(.init(catching: execute))
        : self.eventLoop.submit(execute)
    }
}

extension ChannelPipeline.SynchronousOperations {
    
    public func addHTTPProxyClientHandlers(logger: Logger,
                                           taskAddress: NetAddress,
                                           authorization: BasicAuthorization? = nil,
                                           position: ChannelPipeline.Position = .last) throws {
        eventLoop.assertInEventLoop()
        let handlers: [ChannelHandler] = [HTTP1ClientCONNECTTunnelHandler(logger: logger, taskAddress: taskAddress, authorization: authorization)]
        try self.addHTTPClientHandlers()
        try self.addHandlers(handlers, position: position)
    }
    
    public func configureHTTPProxyServerPipeline(logger: Logger,
                                                 authorization: BasicAuthorization? = nil,
                                                 enableHTTPCapture: Bool = false,
                                                 enableMitM: Bool = false,
                                                 mitmConfig: MitMConfiguration? = nil,
                                                 position: ChannelPipeline.Position = .last,
                                                 completion: @escaping (Request) -> EventLoopFuture<Channel>) throws {
        self.eventLoop.assertInEventLoop()
        
        let responseEncoder = HTTPResponseEncoder()
        let requestDecoder = HTTPRequestDecoder(leftOverBytesStrategy: .forwardBytes)
        
        let serverHandler = HTTPProxyServerHandler(logger: logger, authorization: authorization, outEFLBuilder: completion) { req, channel in
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
                guard $0.key.hasPrefix("*.") else {
                    return $0.key == serverHostname
                }
                return serverHostname.contains($0.key.suffix(from: $0.key.index($0.key.startIndex, offsetBy: 2)))
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
