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

final public class HTTPProxyServerHandler: ChannelInboundHandler, RemovableChannelHandler {
    
    public typealias InboundIn = HTTPServerRequestPart
    public typealias InboundOut = HTTPServerRequestPart
    public typealias OutboundOut = HTTPServerResponsePart
    
    private var state: ConnectionState
    
    /// The task request head part. this value is updated after `head` part received.
    private var headPart: HTTPRequestHead!
    
    private enum Event {
        case channelRead(data: NIOAny)
        case channelReadComplete
    }
    
    /// When a proxy request is received, we will send a new request to the target server.
    /// During the request is established, we need to buffer events.
    private var eventBuffer: CircularBuffer<Event> = .init(initialCapacity: 0)
    
    /// The Logger for this handler.
    public let logger: Logger
    
    public let completion: (Request, Channel) throws -> Void
    
    /// The credentials to authenticate a user.
    public let authorization: BasicAuthorization?
    
    private var outEFLBuilder: (Request) -> EventLoopFuture<Channel>
    
    public init(logger: Logger,
                authorization: BasicAuthorization? = nil,
                outEFLBuilder: @escaping (Request) -> EventLoopFuture<Channel>,
                completion: @escaping (Request, Channel) throws -> Void) {
        self.logger = logger
        self.authorization = authorization
        self.outEFLBuilder = outEFLBuilder
        self.completion = completion
        self.state = .idle
    }
    
    public func handlerAdded(context: ChannelHandlerContext) {
        startHandshaking(context: context)
    }
    
    public func channelActive(context: ChannelHandlerContext) {
        startHandshaking(context: context)
        context.fireChannelActive()
    }
    
    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard state != .active else {
            // All inbound events will be buffered until handle remove from pipeline.
            eventBuffer.append(.channelRead(data: data))
            return
        }
        
        do {
            switch unwrapInboundIn(data) {
                case .head(let head) where state == .evaluating:
                    headPart = head
                    guard head.method != .CONNECT else {
                        return
                    }
                    // Strip hop-by-hop header based on rfc2616.
                    headPart.headers = headPart.headers.trimmingFieldsInHopByHop()
                    
                    eventBuffer.append(.channelRead(data: wrapInboundOut(.head(headPart))))
                    try evaluateClientGreeting(context: context)
                    
                case .body where headPart != nil && headPart.method != .CONNECT:
                    eventBuffer.append(.channelRead(data: data))
                case .end where headPart != nil:
                    guard headPart.method != .CONNECT else {
                        try evaluateClientGreeting(context: context)
                        return
                    }
                    eventBuffer.append(.channelRead(data: data))
                    
                default:
                    throw HTTPProxyError.invalidHTTPOrdering
            }
        } catch {
            deliverOneError(error, context: context)
        }
    }
    
    public func channelReadComplete(context: ChannelHandlerContext) {
        // All events will be buffered before the `self.state` becomes `active`.
        // After the state becomes active, the handler will be automatically removed
        // and all cached events will be unbuffered, so we only need buffer this
        // event at this time.
        eventBuffer.append(.channelReadComplete)
    }
    
    public func removeHandler(context: ChannelHandlerContext, removalToken: ChannelHandlerContext.RemovalToken) {
        assert(state == .active, "\(self) should never remove before proxy pipe active.")
        
        // We're being removed from the pipeline. If we have buffered events, deliver them.
        while !eventBuffer.isEmpty {
            switch eventBuffer.removeFirst() {
                case .channelRead(data: let data):
                    context.fireChannelRead(data)
                case .channelReadComplete:
                    context.fireChannelReadComplete()
            }
        }
        
        context.leavePipeline(removalToken: removalToken)
    }
}

extension HTTPProxyServerHandler {
    
    private func startHandshaking(context: ChannelHandlerContext) {
        guard context.channel.isActive, state == .idle else {
            return
        }
        do {
            try state.evaluating()
        } catch {
            deliverOneError(error, context: context)
        }
    }
    
    private func evaluateClientGreeting(context: ChannelHandlerContext) throws {
        guard let head = headPart else {
            throw HTTPProxyError.invalidURL(url: "nil")
        }
        
        // Only CONNECT tunnel need remove default http server pipelines.
        if headPart.method == .CONNECT {
            // New request is complete. We don't want any more data from now on.
            context.pipeline.handler(type: ByteToMessageHandler<HTTPRequestDecoder>.self)
                .whenSuccess { httpDecoder in
                    context.pipeline.removeHandler(httpDecoder, promise: nil)
                }
        }
        
        // Proxy Authorization
        if let authorization = authorization {
            guard let basicAuthorization = head.headers.basicAuthorization else {
                throw HTTPProxyError.unacceptable(code: .proxyAuthenticationRequired)
            }
            guard authorization == basicAuthorization else {
                throw HTTPProxyError.unacceptable(code: .unauthorized)
            }
        }
        
        let req = Request.init(head: head)
        
        self.outEFLBuilder(req).whenComplete {
            switch $0 {
                case .success(let channel):
                    self.pipe(req, channel: channel, context: context)
                case .failure(let error):
                    self.deliverOneError(error, context: context)
            }
        }
    }
    
    private func pipe(_ request: Request, channel: Channel, context: ChannelHandlerContext) {
        logger.info("Tunneling request to \(request.uri) via \(String(describing: channel.remoteAddress))")
        
        do {
            try state.established()
        } catch {
            deliverOneError(error, context: context)
        }
        
        let promise = context.eventLoop.makePromise(of: Void.self)
        
        // Only CONNECT tunnel need established response and remove default http server pipelines.
        if headPart.method == .CONNECT {
            // Ok, upgrade has completed! We now need to begin the upgrade process.
            // First, send the 200 connection established message.
            // This content-length header is MUST NOT, but we need to workaround NIO's insistence that we set one.
            var headers = HTTPHeaders()
            headers.add(name: .contentLength, value: "0")
            let head = HTTPResponseHead(version: .http1_1, status: .ok, headers: headers)
            context.write(wrapOutboundOut(.head(head)), promise: nil)
            context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
            
            context.pipeline.handler(type: HTTPResponseEncoder.self)
                .flatMap(context.pipeline.removeHandler)
                .cascade(to: promise)
        } else {
            promise.succeed(())
        }
        
        let (localGlue, peerGlue) = GlueHandler.matchedPair()
        promise.futureResult
            .flatMapThrowing {
                try self.completion(request, channel)
                try context.pipeline.syncOperations.addHandler(localGlue)
                try channel.pipeline.syncOperations.addHandler(peerGlue)
            }
            .flatMap {
                context.pipeline.removeHandler(self)
            }
            .whenFailure { error in
                // Close connected peer channel before closing our channel.
                channel.close(promise: nil)
                self.deliverOneError(error, context: context)
            }
    }
    
    private func deliverOneError(_ error: Error, context: ChannelHandlerContext) {
        logger.error("\(error)")
        
        var head: HTTPResponseHead?
        
        if let err = error as? HTTPProxyError {
            switch err {
                case .invalidProxyResponse(let response):
                    head = response
                case .invalidClientState, .invalidServerState, .invalidHTTPOrdering:
                    head = HTTPResponseHead.init(version: .http1_1, status: .internalServerError)
                case .unacceptable(code: let code):
                    head = HTTPResponseHead.init(version: .http1_1, status: code)
                case .invalidURL:
                    var headers = HTTPHeaders.init()
                    headers.add(name: .proxyConnection, value: "close")
                    headers.add(name: .connection, value: "close")
                    head = HTTPResponseHead.init(version: .http1_1, status: .badRequest, headers: headers)
            }
        }
        
        if let head = head {
            context.write(wrapOutboundOut(.head(head)), promise: nil)
            context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
        }
        
        context.fireErrorCaught(error)
        context.close(promise: nil)
    }
}

extension HTTPHeaders {
    
    /// Returns a new HTTPHeaders made by removing from all hop-by-hop fields.
    /// - Returns: The headers without hop-by-hop fields.
    func trimmingFieldsInHopByHop() -> HTTPHeaders {
        var headers = self
        headers.remove(name: .proxyConnection)
        headers.remove(name: .proxyAuthenticate)
        headers.remove(name: .proxyAuthorization)
        headers.remove(name: .te)
        headers.remove(name: .trailer)
        headers.remove(name: .transferEncoding)
        headers.remove(name: .upgrade)
        headers.remove(name: .connection)
        return headers
    }
}