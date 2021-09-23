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
import NIOSSL
import NIOTLS

extension ChannelPipeline {
    
    func addSSLClientHandlers(tlsConfiguration: TLSConfiguration = .makeClientConfiguration(), serverHostname: String? = nil, position: ChannelPipeline.Position = .last) -> EventLoopFuture<Void> {
        if eventLoop.inEventLoop {
            let result = Result<Void, Error> {
                try syncOperations.addSSLClientHandlers(tlsConfiguration: tlsConfiguration, serverHostname: serverHostname, position: position)
            }
            return eventLoop.makeCompletedFuture(result)
        } else {
            return eventLoop.submit({
                try self.syncOperations.addSSLClientHandlers(tlsConfiguration: tlsConfiguration, serverHostname: serverHostname, position: position)
            })
        }
    }
    
    func configureSSLServerHandlers(certificateChain: [NIOSSLCertificateSource], privateKey: NIOSSLPrivateKeySource, position: ChannelPipeline.Position = .last) -> EventLoopFuture<Void> {
        let tlsConfiguration = TLSConfiguration.makeServerConfiguration(certificateChain: certificateChain, privateKey: privateKey)
        return configureSSLServerHandlers(tlsConfiguration: tlsConfiguration, position: position)
    }
    
    func configureSSLServerHandlers(tlsConfiguration: TLSConfiguration, position: ChannelPipeline.Position = .last) -> EventLoopFuture<Void> {
        if eventLoop.inEventLoop {
            let result = Result<Void, Error> {
                try syncOperations.configureSSLServerHandlers(tlsConfiguration: tlsConfiguration, position: position)
            }
            return eventLoop.makeCompletedFuture(result)
        } else {
            return eventLoop.submit {
                try self.syncOperations.configureSSLServerHandlers(tlsConfiguration: tlsConfiguration, position: position)
            }
        }
    }
}

extension ChannelPipeline.SynchronousOperations {
            
    func addSSLClientHandlers(tlsConfiguration: TLSConfiguration = .makeClientConfiguration(), serverHostname: String? = nil, position: ChannelPipeline.Position = .last) throws {
        eventLoop.assertInEventLoop()
        
        let sslContext = try NIOSSLContext(configuration: tlsConfiguration)
        let sslHandler = try NIOSSLClientHandler(context: sslContext, serverHostname: serverHostname)
        let apnHandler = ApplicationProtocolNegotiationHandler { result, channel in
            channel.pipeline.eventLoop.makeSucceededVoidFuture()
        }
        let handlers: [ChannelHandler] = [sslHandler, apnHandler]
        
        try addHandlers(handlers, position: position)
    }
    
    func configureSSLServerHandlers(certificateChain: [NIOSSLCertificateSource], privateKey: NIOSSLPrivateKeySource, position: ChannelPipeline.Position = .last) throws {
        eventLoop.assertInEventLoop()
        
        let tlsConfiguration = TLSConfiguration.makeServerConfiguration(certificateChain: certificateChain, privateKey: privateKey)
        
        try configureSSLServerHandlers(tlsConfiguration: tlsConfiguration, position: position)
    }
    
    func configureSSLServerHandlers(tlsConfiguration: TLSConfiguration, position: ChannelPipeline.Position = .last) throws {
        eventLoop.assertInEventLoop()
        
        let sslContext = try NIOSSLContext(configuration: tlsConfiguration)
        let sslHandler = NIOSSLServerHandler(context: sslContext)
        let apnHandler = ApplicationProtocolNegotiationHandler { result, channel in
            channel.pipeline.eventLoop.makeSucceededVoidFuture()
        }
        let handlers: [ChannelHandler] = [sslHandler, apnHandler]
        
        try addHandlers(handlers, position: position)
    }
}
