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

import Foundation
import Logging
import NIO
import NIOHTTP1
import NIOSSL

final public class HTTP1ProxyServerHandler: ChannelInboundHandler, RemovableChannelHandler {
    
    public typealias InboundIn = HTTPServerRequestPart
    public typealias InboundOut = HTTPServerRequestPart
    public typealias OutboundOut = HTTPServerResponsePart
    
    private var state: ConnectionState
    
    /// The task request head part. this value is updated after `head` part received.
    private var requestHead: HTTPRequestHead!
    
    private enum Event {
        case channelRead(data: NIOAny)
        case channelReadComplete
    }
    
    /// When a proxy request is received, we will send a new request to the target server.
    /// During the request is established, we need to buffer events.
    private var eventBuffer: CircularBuffer<Event> = .init(initialCapacity: 0)
    
    /// The Logger for this handler.
    public let logger: Logger
    
    public let completion: (NetAddress) -> EventLoopFuture<Channel>
    
    /// Enable  to allow MitM decrypt https triffic.
    public let isMitMEnabled: Bool
    
    /// Enable  to capture http body.
    public let isHTTPCaptureEnabled: Bool
    
    /// Configuration for HTTP traffic with MitM attacks.
    public let mitmConfiguration: MitMConfiguration?
    
    /// The credentials to authenticate a user.
    public let authorization: BasicAuthorization?
    
    public init(logger: Logger,
                authorization: BasicAuthorization? = nil,
                enableHTTPCapture: Bool = false,
                enableMitM: Bool = false,
                mitmConfig: MitMConfiguration? = nil,
                completion: @escaping (NetAddress) -> EventLoopFuture<Channel>) {
        self.logger = logger
        self.authorization = authorization
        self.isHTTPCaptureEnabled = enableHTTPCapture
        self.isMitMEnabled = enableMitM
        self.mitmConfiguration = mitmConfig
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
                    requestHead = head
                    guard head.method != .CONNECT else {
                        if !isMitMEnabled {
                            // CONNECT pipeline doesn't contains `HTTPContentCather` handler when MitM disabled.
                            // so we need log msg in there.
                            var msg = "\n"
                            msg += "\n\(head.method) \(head.version) \(head.uri)"
                            head.headers.forEach { field in
                                msg += "\n"
                                msg += "\(field.name) \(field.value)"
                            }
//                            logger.info("\(msg)")
                        }
                        return
                    }
                    // Strip hop-by-hop header based on rfc2616.
                    requestHead.headers = requestHead.headers.trimmingFieldsInHopByHop()
                    
                    eventBuffer.append(.channelRead(data: wrapInboundOut(.head(requestHead))))
                    try evaluateClientGreeting(context: context)
                    
                case .body where requestHead != nil && requestHead.method != .CONNECT:
                    eventBuffer.append(.channelRead(data: data))
                    
                case .end(let trailers) where requestHead != nil:
                    guard requestHead.method != .CONNECT else {
                        try evaluateClientGreeting(context: context)
                        if !isMitMEnabled {
                            var msg = "\n"
                            trailers?.forEach { field in
                                msg += "\n"
                                msg += "\(field.name) \(field.value)"
                            }
                            msg += "\n"
//                            logger.info("\(msg)")
                        }
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

extension HTTP1ProxyServerHandler {
    
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
        guard let head = requestHead else {
            throw HTTPProxyError.invalidURL(url: "nil")
        }
        
        // Only CONNECT tunnel need remove default http server pipelines.
        if requestHead.method == .CONNECT {
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
        
        guard let serverHostname = head.host, !serverHostname.isEmpty else {
            // RFC 2068 (HTTP/1.1) requires URL to be absolute URL in HTTP proxy.
            throw HTTPProxyError.invalidURL(url: head.uri)
        }
        
        let taskAddress: NetAddress = .domainPort(serverHostname, head.port)
        
        let client = completion(taskAddress)
        
        client.whenSuccess { channel in
            self.remoteDidConnected(serverHostname, channel: channel, context: context)
        }
        
        client.whenFailure { error in
            self.deliverOneError(error, context: context)
        }
    }
    
    private func remoteDidConnected(_ serverHostname: String, channel: Channel, context: ChannelHandlerContext) {
        logger.trace("proxy server connected \(String(describing: channel.remoteAddress?.description))")
        
        do {
            try state.established()
        } catch {
            deliverOneError(error, context: context)
        }
        
        let promise = context.eventLoop.makePromise(of: Void.self)
        
        // Only CONNECT tunnel need established response and remove default http server pipelines.
        if requestHead.method == .CONNECT {
            logger.trace("sending establish message to \(String(describing: context.channel.localAddress))...")
            // Ok, upgrade has completed! We now need to begin the upgrade process.
            // First, send the 200 connection established message.
            // This content-length header is MUST NOT, but we need to workaround NIO's insistence that we set one.
            var headers = HTTPHeaders()
            headers.add(name: .contentLength, value: "0")
            let head = HTTPResponseHead(version: .http1_1, status: .custom(code: 200, reasonPhrase: "Connection Established"), headers: headers)
            context.write(wrapOutboundOut(.head(head)), promise: nil)
            context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
            
            context.pipeline.handler(type: HTTPResponseEncoder.self)
                .flatMap(context.pipeline.removeHandler)
                .cascade(to: promise)
        } else {
            promise.succeed(())
        }
        
        promise.futureResult
            .flatMapThrowing {
                let (localGlue, peerGlue) = GlueHandler.matchedPair()
                
                // Only support CONNECT tunnel SSL decryption.
                let isMitMEnabled = self.isMitMEnabled && self.requestHead.method == .CONNECT
                
                var filtered: [String : NIOSSLPKCS12Bundle]?
                
                // Only filter PKCS#12 bundle when `isMitMEnabled` set to true.
                if isMitMEnabled {
                    filtered = self.mitmConfiguration?.pool.filter {
                        if $0.key.hasPrefix("*") {
                            return serverHostname.contains($0.key.dropFirst())
                        }
                        return $0.key == serverHostname
                    }
                }
                
                guard isMitMEnabled, let bundle = filtered?.first?.value else {
                    if self.requestHead.method != .CONNECT {
                        try context.pipeline.syncOperations.addHandlers([
                            HTTPContentCatcher<HTTPRequestHead>.init(enableHTTPCapture: self.isHTTPCaptureEnabled),
                            HTTPIOTransformer<HTTPRequestHead>()
                        ])
                        
                        try channel.pipeline.syncOperations.addHTTPClientHandlers()
                        try channel.pipeline.syncOperations.addHandlers([
                            HTTPContentCatcher<HTTPResponseHead>.init(enableHTTPCapture: self.isHTTPCaptureEnabled),
                            HTTPIOTransformer<HTTPResponseHead>()
                        ])
                    }
                    try context.pipeline.syncOperations.addHandler(localGlue)
                    try channel.pipeline.syncOperations.addHandler(peerGlue)
                    return
                }
                
                try context.pipeline.syncOperations.configureSSLServerHandlers(pkcs12Bundle: bundle)
                try context.pipeline.syncOperations.configureHTTPServerPipeline(withPipeliningAssistance: false, withErrorHandling: false)
                try context.pipeline.syncOperations.addHandler(HTTPContentCatcher<HTTPRequestHead>.init(enableHTTPCapture: self.isHTTPCaptureEnabled))
                try context.pipeline.syncOperations.addHandlers([HTTPIOTransformer<HTTPRequestHead>(), localGlue])
                
                try channel.pipeline.syncOperations.addSSLClientHandlers(serverHostname: serverHostname)
                try channel.pipeline.syncOperations.addHTTPClientHandlers()
                try channel.pipeline.syncOperations.addHandler(HTTPContentCatcher<HTTPResponseHead>.init(enableHTTPCapture: self.isHTTPCaptureEnabled))
                try channel.pipeline.syncOperations.addHandlers([HTTPIOTransformer<HTTPResponseHead>(), peerGlue])
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
    fileprivate func trimmingFieldsInHopByHop() -> HTTPHeaders {
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

extension HTTPRequestHead {
    
    public var host: String? {
        return headers.first(name: .host)?.components(separatedBy: ":").first
    }
    
    /// Port for request. parse from `headers` host filed or `uri` if any else 80 is returned.
    public var port: Int {
        var part = headers.first(name: .host)?.components(separatedBy: ":")
        
        // Standard host field
        if part?.count == 2 {
            return Int(part![1])!
        }
        
        part = uri.components(separatedBy: ":")
        
        guard part?.count == 2 else {
            return 80
        }
        
        return Int(part![1].split(separator: "/").first!) ?? 80
    }
}
