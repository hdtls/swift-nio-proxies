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

import NIO
import NIOHTTP1
import Logging
import Helpers

public final class HTTP1ServerCONNECTTunnelHandler: ChannelInboundHandler, RemovableChannelHandler {
    
    public typealias InboundIn = HTTPServerRequestPart
    public typealias OutboundOut = HTTPServerResponsePart
    
    private var state: ServerStateMachine
    
    /// The task uri for truly http request. this value is updated after  `head` part received.
    private var uri: String?
    
    /// When a proxy request is received, we will send a new request to the target server.
    /// During the request is established, we need to cache the proxy request data.
    private var readBuffers: CircularBuffer<NIOAny> = .init()
    
    public let logger: Logger
    
    public let completion: (String) -> EventLoopFuture<Channel>
    
    public init(logger: Logger = .init(label: "com.netbot.http-server-tunnel"), completion: @escaping (String) -> EventLoopFuture<Channel>) {
        self.logger = logger
        self.completion = completion
        self.state = ServerStateMachine()
    }
    
    public func handlerAdded(context: ChannelHandlerContext) {
        beginHandshake(context: context)
    }
    
    public func channelActive(context: ChannelHandlerContext) {
        beginHandshake(context: context)
        context.fireChannelActive()
    }
    
    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard !state.shouldBufferRead, readBuffers.isEmpty else {
            if readBuffers.isEmpty {
                context.fireChannelRead(data)
            } else {
                readBuffers.append(data)
            }
            return
        }
        
        do {
            let action = try state.receiveHTTPPart(unwrapInboundIn(data))
            try handleAction(action, context: context)
        } catch {
            deliverOneError(error, context: context)
        }
    }
    
    public func removeHandler(context: ChannelHandlerContext, removalToken: ChannelHandlerContext.RemovalToken) {
        defer {
            context.leavePipeline(removalToken: removalToken)
        }
        
        guard state.proxyEstablished, !readBuffers.isEmpty else {
            return
        }
        
        // We're being removed from the pipeline. If we have buffered events, deliver them.
        while !readBuffers.isEmpty {
            context.fireChannelRead(readBuffers.removeFirst())
        }
    }
    
}

extension HTTP1ServerCONNECTTunnelHandler {
    
    private func beginHandshake(context: ChannelHandlerContext) {
        guard context.channel.isActive else {
            return
        }
        do {
            try state.connectionEstablished()
        } catch {
            deliverOneError(error, context: context)
        }
    }
    
    private func handleAction(_ action: ServerAction, context: ChannelHandlerContext) throws {
        switch action {
            case .deliverOneHTTPRequestHeadPart(head: let head):
                try handleHTTPHeadPartReceive(head)
            case .deliverOneHTTPRequestEndPart(headers: let headers):
                try handleHTTPEndPartReceive(headers, context: context)
        }
    }
    
    private func handleHTTPHeadPartReceive(_ head: HTTPRequestHead) throws {
        logger.info("\(head.method) \(head.uri) \(head.version)")
        
        guard head.method == .CONNECT else {
            logger.debug("unsupported HTTP proxy method: \(head.method)")
            throw HTTPProxyError.unsupportedHTTPProxyMethod
        }
        
        uri = head.uri
    }
    
    private func handleHTTPEndPartReceive(_ headers: HTTPHeaders?, context: ChannelHandlerContext) throws {
        // New request is complete. We don't want any more data from now on.
        context.pipeline.handler(type: ByteToMessageHandler<HTTPRequestDecoder>.self)
            .whenSuccess { httpDecoder in
                context.pipeline.removeHandler(httpDecoder, promise: nil)
            }
        
        guard let uri = uri else {
            // TODO: Invalid uri error handling
            deliverOneError(HTTPProxyError.unexpectedRead, context: context)
            return
        }
        
        let client = completion(uri)
        logger.info("connecting to proxy server...")
        
        client.whenSuccess { channel in
            self.handleRemoteConnect(peerChannel: channel, context: context)
        }
        
        client.whenFailure { error in
            self.deliverOneError(error, context: context)
        }
    }
    
    private func handleRemoteConnect(peerChannel: Channel, context: ChannelHandlerContext) {
        logger.info("proxy server connected \(peerChannel.remoteAddress?.description ?? "")")
        
        do {
            try state.sendServerGreeting()
        } catch {
            deliverOneError(error, context: context)
        }
        
        logger.info("sending establish message to \(String(describing: context.channel.localAddress))...")
        // Ok, upgrade has completed! We now need to begin the upgrade process.
        // First, send the 200 message.
        // This content-length header is MUST NOT, but we need to workaround NIO's insistence that we set one.
        let headers = HTTPHeaders([("Content-Length", "0")])
        let head = HTTPResponseHead(version: .http1_1, status: .ok, headers: headers)
        context.write(wrapOutboundOut(.head(head)), promise: nil)
        context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
        
        let (localGlue, peerGlue) = GlueHandler.matchedPair()
        
        context.pipeline.handler(type: HTTPResponseEncoder.self)
            .flatMap {
                context.pipeline.removeHandler($0)
            }
            .flatMap {
                // Now we need to glue our channel and the peer channel together.
                context.channel.pipeline.addHandler(localGlue)
                    .and(peerChannel.pipeline.addHandler(peerGlue))
            }
            .flatMap { _ in
                context.pipeline.removeHandler(self)
            }
            .whenFailure { error in
                // Close connected peer channel before closing our channel.
                peerChannel.close(mode: .all, promise: nil)
                self.deliverOneError(error, context: context)
            }
    }
    
    private func deliverOneError(_ error: Error, context: ChannelHandlerContext) {
        logger.error("\(error)")
        context.close(promise: nil)
        context.fireErrorCaught(error)
    }
    
    public func errorCaught(context: ChannelHandlerContext, error: Error) {
        logger.error("\(error)")
        context.fireErrorCaught(error)
    }
}
