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

public class HTTPServerProxyHandler: ChannelInboundHandler, RemovableChannelHandler {
    
    public typealias InboundIn = HTTPServerRequestPart
    public typealias OutboundOut = HTTPServerResponsePart
    
    /// The state of the HTTP connection.
    private enum ConnectionState {
        /// We are waiting for a HTTP response to complete before we
        /// let the next request in.
        case responseEndPending
        
        /// We are in the middle of both a request and a response and waiting for both `.end`s.
        case requestAndResponseEndPending
        
        /// Nothing is active on this connection, the next message we expect would be a request `.head`.
        case idle
        
        /// The server has responded early, before the request has completed. We need
        /// to wait for the request to complete, but won't block anything.
        case requestEndPending
        
        mutating func requestHeadReceived() {
            switch self {
                case .idle:
                    self = .requestAndResponseEndPending
                case .requestAndResponseEndPending, .responseEndPending, .requestEndPending:
                    preconditionFailure("received request head in state \(self)")
            }
        }
        
        mutating func responseEndReceived() {
            switch self {
                case .responseEndPending:
                    // Got the response we were waiting for.
                    self = .idle
                case .requestAndResponseEndPending:
                    // We got a response while still receiving a request, which we have to
                    // wait for.
                    self = .requestEndPending
                case .requestEndPending, .idle:
                    preconditionFailure("Unexpectedly received a response in state \(self)")
            }
        }
        
        mutating func requestEndReceived() {
            switch self {
                case .requestEndPending:
                    // Got the request end we were waiting for.
                    self = .idle
                case .requestAndResponseEndPending:
                    // We got a request and the response isn't done, wait for the
                    // response.
                    self = .responseEndPending
                case .responseEndPending, .idle:
                    preconditionFailure("Received second request")
            }
        }
    }
    
    /// The events that this handler buffers while waiting for the server to
    /// generate a response.
    private enum BufferedEvent {
        /// A channelRead event.
        case channelRead(NIOAny)
        
        case error(HTTPParserError)
        
        /// A TCP half-close. This is buffered to ensure that subsequent channel
        /// handlers that are aware of TCP half-close are informed about it in
        /// the appropriate order.
        case halfClose
    }
    
    private var state: ConnectionState = .idle
    
    /// The buffered HTTP requests that are not going to be addressed yet. In general clients
    /// don't pipeline, so this initially allocates no space for data at all. Clients that
    /// do pipeline will cause dynamic resizing of the buffer, which is generally acceptable.
    private var eventBuffer = CircularBuffer<BufferedEvent>(initialCapacity: 0)
    
    private var bufferedWrites: MarkedCircularBuffer<(NIOAny, EventLoopPromise<Void>?)> = .init(initialCapacity: 8)
    
    public let logger: Logger
    
    public let completion: (Result<HTTPRequestHead, HTTPProxyError>) -> EventLoopFuture<Channel>
    
    public init(logger: Logger = .init(label: "com.netbot.socks-logging"), completion: @escaping (Result<HTTPRequestHead, HTTPProxyError>) -> EventLoopFuture<Channel>) {
        self.logger = logger
        self.completion = completion
    }
    
    public func handlerAdded(context: ChannelHandlerContext) {
        _ = context.pipeline.addHandlers([
            HTTPResponseEncoder(),
            ByteToMessageHandler(HTTPRequestDecoder(leftOverBytesStrategy: .forwardBytes))
        ], position: .before(self))
    }
    
    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        if eventBuffer.count != 0 || self.state == .responseEndPending {
            eventBuffer.append(.channelRead(data))
            return
        } else {
            switch unwrapInboundIn(data) {
                case .head(let head):
                    //                    guard head.uri == "www.baidu.com:443" else { return }
                    //                    filtered = false
                    deliverOneHTTPHeadMsg(context: context, head: head)
                case .body:
                    ()
                case .end(let headers):
                    //                    guard !filtered else { return }
                    deliverOneHTTPEndMsg(context: context, headers: headers)
            }
        }
    }
    
    func deliverOneHTTPHeadMsg(context: ChannelHandlerContext, head: HTTPRequestHead) {
        state.requestHeadReceived()
        logger.info("\(head.method) \(head.uri) \(head.version)")
        
        guard head.method == .CONNECT else {
            logger.debug("unsupported HTTP proxy method: \(head.method)")
            deliverOneError(context: context, error: HTTPProxyError.unsupportedHTTPProxyMethod)
            return
        }
        
        let eventLoopFuture = completion(.success(head))
        
        eventLoopFuture.whenSuccess { peerChannel in
            self.handlePeer(peerChannel: peerChannel, context: context)
        }
        
        eventLoopFuture.whenFailure { error in
            self.deliverOneError(context: context, error: error)
        }
    }
    
    func deliverOneHTTPEndMsg(context: ChannelHandlerContext, headers: HTTPHeaders?) {
        // New request is complete. We don't want any more data from now on.
        state.requestEndReceived()
        context.pipeline.handler(type: ByteToMessageHandler<HTTPRequestDecoder>.self)
            .whenSuccess { httpDecoder in
                context.pipeline.removeHandler(httpDecoder, promise: nil)
            }
    }
    
    func handlePeer(peerChannel: Channel, context: ChannelHandlerContext) {
        // Ok, upgrade has completed! We now need to begin the upgrade process.
        // First, send the 200 message.
        // This content-length header is MUST NOT, but we need to workaround NIO's insistence that we set one.
        let headers = HTTPHeaders([("Content-Length", "0")])
        let head = HTTPResponseHead(version: .http1_1, status: .ok, headers: headers)
        logger.info("sending establish message...")
        
        context.write(self.wrapOutboundOut(.head(head)), promise: nil)
        context.writeAndFlush(self.wrapOutboundOut(.end(nil)), promise: nil)
        
        context.pipeline.handler(type: HTTPResponseEncoder.self)
            .whenSuccess { httpEncoder in
                context.pipeline.removeHandler(httpEncoder, promise: nil)
            }
        
        // Now we need to glue our channel and the peer channel together.
        let (localGlue, peerGlue) = GlueHandler.matchedPair()
        context.channel.pipeline.addHandler(localGlue)
            .and(peerChannel.pipeline.addHandler(peerGlue))
            .whenComplete { result in
                switch result {
                    case .success(_):
                        context.pipeline.removeHandler(self, promise: nil)
                    case .failure(_):
                        // Close connected peer channel before closing our channel.
                        peerChannel.close(mode: .all, promise: nil)
                        context.close(promise: nil)
                }
            }
    }
    
    private func deliverOneError(context: ChannelHandlerContext, error: Error) {
        // there is one interesting case in this error sending logic: If we receive a `HTTPParserError` and we haven't
        // received a full request nor the beginning of a response we should treat this as a full request. The reason
        // is that what the user will probably do is send a `.badRequest` response and we should be in a state which
        // allows that.
        if (self.state == .idle || self.state == .requestEndPending) && error is HTTPParserError {
            self.state = .responseEndPending
        }
        
        logger.error("\(error)")
        context.fireErrorCaught(error)
    }
    
    public func errorCaught(context: ChannelHandlerContext, error: Error) {
        guard let httpError = error as? HTTPParserError else {
            self.deliverOneError(context: context, error: error)
            return
        }
        if case .responseEndPending = self.state {
            self.eventBuffer.append(.error(httpError))
            return
        }
        self.deliverOneError(context: context, error: error)
    }
    
    public func handlerRemoved(context: ChannelHandlerContext) {
        // We're being removed from the pipeline. We need to do a few things:
        //
        // 1. If we have buffered events, deliver them. While we shouldn't be
        //     re-entrantly called, we want to ensure that so we take a local copy.
        // 2. If we are quiescing, we swallowed a quiescing event from the user: replay it,
        //     as the user has hopefully added a handler that will do something with this.
        // 3. Finally, if we have a read pending, we need to release it.
        //
        // The basic theory here is that if there is anything we were going to do when we received
        // either a request .end or a response .end, we do it now because there is no future for us.
        // We also need to ensure we do not drop any data on the floor.
        //
        // At this stage we are no longer in the pipeline, so all further content should be
        // blocked from reaching us. Thus we can avoid mutating our own internal state any
        // longer.
        
        for event in eventBuffer {
            switch event {
                case .channelRead(let read):
                    context.fireChannelRead(read)
                case .halfClose:
                    context.fireUserInboundEventTriggered(ChannelEvent.inputClosed)
                case .error(let error):
                    context.fireErrorCaught(error)
            }
        }
    }
}
