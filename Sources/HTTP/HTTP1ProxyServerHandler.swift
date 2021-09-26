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

#if compiler(>=5.1)
@_implementationOnly import CNIOBoringSSL
#else
import CNIOBoringSSL
#endif
import Foundation
import Helpers
import Logging
import NIO
import NIOHTTP1
import NIOSSL

public final class HTTP1ProxyServerHandler: ChannelInboundHandler, RemovableChannelHandler {
    
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
    
    public let logger: Logger
    
    public let completion: (NetAddress) -> EventLoopFuture<Channel>
    
    /// Enable this to allow MitM decrypt https triffic.
    public let isMitMEnabled: Bool = false
    
    /// Enable this to capture http body.
    public let isHTTPCaptureEnabled: Bool = true
    
    public let sslDecConfig: SSLDecryptionConfiguration = .init(skipServerCertificateVerification: true, hostnames: ["*.baidu.com", "*.ietf.org"], base64EncodedP12String: "", passphrase: "")
    
    public init(logger: Logger = .init(label: "com.netbot.http-tunnel"), enableHTTPCapture: Bool = false, enableMitM: Bool = false, completion: @escaping (NetAddress) -> EventLoopFuture<Channel>) {
        self.logger = logger
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
            eventBuffer.append(.channelRead(data: data))
            return
        }
        
        do {
            switch unwrapInboundIn(data) {
                case .head(let head) where state == .evaluating:
                    requestHead = head
                    guard head.method != .CONNECT else {
                        return
                    }
                    // Strip hop-by-hop header based on rfc2616.
                    requestHead.headers = requestHead.headers.trimmingFieldsInHopByHop()
                    
                    eventBuffer.append(.channelRead(data: wrapInboundOut(.head(requestHead))))
                    try evaluateClientGreeting(context: context)
                    
                case .body where requestHead != nil && requestHead.method != .CONNECT:
                    eventBuffer.append(.channelRead(data: data))
                    
                case .end where requestHead != nil:
                    guard requestHead.method != .CONNECT else {
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
        precondition(state == .active, "\(self) should never remove before proxy pipe active.")
        
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
        
        logger.info("\(head.method) \(head.uri) \(head.version)")
        
        // Only CONNECT tunnel need remove default http server pipelines.
        if requestHead.method == .CONNECT {
            // New request is complete. We don't want any more data from now on.
            context.pipeline.handler(type: ByteToMessageHandler<HTTPRequestDecoder>.self)
                .whenSuccess { httpDecoder in
                    context.pipeline.removeHandler(httpDecoder, promise: nil)
                }
        }
        
        // Proxy Authorization
        if let authorization = head.headers.first(name: "Proxy-Authorization") {
            guard false else {
                // If user do not have an authorization msg response 407.
                context.write(wrapOutboundOut(.head(.init(version: .http1_1, status: .proxyAuthenticationRequired, headers: .init()))), promise: nil)
                context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
                return
            }
        }
        
        // This is the easiest way to parse host and port.
        let url = URL(string: "\(head.method == .CONNECT ? "https://" : "")\(head.uri)")
        var serverHostname = url?.host
        if serverHostname == nil, let host = head.headers[canonicalForm: "Host"].first {
            serverHostname = String(host)
        }
        guard let serverHostname = serverHostname, !serverHostname.isEmpty else {
            // RFC 2068 (HTTP/1.1) requires URL to be absolute URL in HTTP proxy.
            throw HTTPProxyError.invalidURL(url: head.uri)
        }
        let port = url?.port ?? (url?.scheme == "https" ? 443 : 80)
        
        let taskAddress: NetAddress = .domainPort(serverHostname, port)
        
        let client = completion(taskAddress)
        
        logger.info("connecting to proxy server...")
        
        client.whenSuccess { channel in
            self.remoteDidConnected(serverHostname, channel: channel, context: context)
        }
        
        client.whenFailure { error in
            self.deliverOneError(error, context: context)
        }
    }
    
    private func remoteDidConnected(_ serverHostname: String, channel: Channel, context: ChannelHandlerContext) {
        logger.info("proxy server connected \(channel.remoteAddress?.description ?? "")")
        
        do {
            try state.established()
        } catch {
            deliverOneError(error, context: context)
        }
        
        let promise = context.eventLoop.makePromise(of: Void.self)
        
        // Only CONNECT tunnel need established response and remove default http server pipelines.
        if requestHead.method == .CONNECT {
            logger.info("sending establish message to \(String(describing: context.channel.localAddress))...")
            // Ok, upgrade has completed! We now need to begin the upgrade process.
            // First, send the 200 connection established message.
            // This content-length header is MUST NOT, but we need to workaround NIO's insistence that we set one.
            let headers = HTTPHeaders([("Content-Length", "0")])
            let head = HTTPResponseHead(version: .http1_1, status: .custom(code: 200, reasonPhrase: "Connection Established"), headers: headers)
            context.write(wrapOutboundOut(.head(head)), promise: nil)
            context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
            
            context.pipeline.handler(type: HTTPResponseEncoder.self)
                .flatMap {
                    context.pipeline.removeHandler($0)
                }.cascade(to: promise)
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
                    filtered = self.sslDecConfig.pool.filter {
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
                case .proxyAuthenticationRequired:
                    head = HTTPResponseHead.init(version: .http1_1, status: .proxyAuthenticationRequired)
                case .invalidURL:
                    var headers = HTTPHeaders.init()
                    headers.add(name: "Proxy-Connection", value: "close")
                    headers.add(name: "Connection", value: "close")
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
        headers.remove(name: "Proxy-Connection")
        headers.remove(name: "Proxy-Authenticate")
        headers.remove(name: "Proxy-Authorization")
        headers.remove(name: "TE")
        headers.remove(name: "Trailers")
        headers.remove(name: "Transfer-Encoding")
        headers.remove(name: "Upgrade")
        headers.remove(name: "Connection")
        return headers
    }
}
