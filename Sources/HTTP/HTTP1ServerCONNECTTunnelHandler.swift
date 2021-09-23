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

public final class HTTP1ServerCONNECTTunnelHandler: ChannelInboundHandler, RemovableChannelHandler {
    
    public typealias InboundIn = HTTPServerRequestPart
    public typealias OutboundOut = HTTPServerResponsePart
    
    private var state: ConnectionState
    
    /// The task request head part. this value is updated after `head` part received.
    private var requestHead: HTTPRequestHead?
    
    /// When a proxy request is received, we will send a new request to the target server.
    /// During the request is established, we need to cache the proxy request data.
    private var readBuffers: CircularBuffer<NIOAny> = .init()
    
    public let logger: Logger
    
    public let completion: (NetAddress) -> EventLoopFuture<Channel>
    
    /// Enable this to allow MitM decrypt https triffic.
    public let isMitMEnabled: Bool = false
    
    /// Enable this to capture http body.
    public let isHTTPCaptureEnabled: Bool = true
    
    public let hostnames: [String] = ["*.ietf.org", "*.baidu.com", "*.akii.me"]
    
    public init(logger: Logger = .init(label: "com.netbot.http-server-tunnel"), completion: @escaping (NetAddress) -> EventLoopFuture<Channel>) {
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
        guard state != .active, readBuffers.isEmpty else {
            if readBuffers.isEmpty {
                context.fireChannelRead(data)
            } else {
                readBuffers.append(data)
            }
            return
        }
        
        do {
            switch unwrapInboundIn(data) {
                case .head(let head) where state == .evaluating:
                    requestHead = head
                case .end where requestHead != nil:
                    try evaluateClientGreeting(context: context)
                default:
                    throw HTTPProxyError.unexpectedRead
            }
        } catch {
            deliverOneError(error, context: context)
        }
    }
    
    public func removeHandler(context: ChannelHandlerContext, removalToken: ChannelHandlerContext.RemovalToken) {
        defer {
            context.leavePipeline(removalToken: removalToken)
        }
        
        guard state == .active, !readBuffers.isEmpty else {
            return
        }
        
        // We're being removed from the pipeline. If we have buffered events, deliver them.
        while !readBuffers.isEmpty {
            context.fireChannelRead(readBuffers.removeFirst())
        }
    }
}

extension HTTP1ServerCONNECTTunnelHandler {
    
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
            throw HTTPProxyError.invalidURL(url: String(describing: requestHead?.uri))
        }
        
        let passingTests = hostnames.contains { hostname in
            head.uri.contains(hostname.replacingOccurrences(of: "*", with: ""))
        }
        guard passingTests else {
            throw HTTPProxyError.invalidURL(url: head.uri)
        }
        
        logger.info("\(head.method) \(head.uri) \(head.version)")
        
        guard head.method == .CONNECT else {
            throw HTTPProxyError.unsupportedHTTPProxyMethod
        }
        
        let splits = head.uri.split(separator: ":")
        guard !splits.isEmpty else {
            throw HTTPProxyError.invalidURL(url: head.uri)
        }
        
        let serverHostname = String(splits.first!)
        let port = Int(splits.last!) ?? 80
        let taskAddress: NetAddress = .domainPort(serverHostname, port)
        
        // New request is complete. We don't want any more data from now on.
        context.pipeline.handler(type: ByteToMessageHandler<HTTPRequestDecoder>.self)
            .whenSuccess { httpDecoder in
                context.pipeline.removeHandler(httpDecoder, promise: nil)
            }
        
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
            }
            .flatMapThrowing {
                let (localGlue, peerGlue) = GlueHandler.matchedPair()
                
                let shouldConfigMitMPipeline = self.isMitMEnabled && self.hostnames.contains { hostname in
                    serverHostname.contains(hostname.replacingOccurrences(of: "*", with: ""))
                }
                
                guard shouldConfigMitMPipeline else {
                    try context.pipeline.syncOperations.addHandler(localGlue)
                    try channel.pipeline.syncOperations.addHandler(peerGlue)
                    return
                }
                
                // Add ssl handlers to decrypt https request.
                let boringSSLIssuedCertificate = try boringSSLIssueSelfSignedCertificate(hostname: serverHostname)
                try context.pipeline.syncOperations.configureSSLServerHandlers(certificateChain: [.certificate(boringSSLIssuedCertificate.0)], privateKey: .privateKey(boringSSLIssuedCertificate.1))
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
                channel.close(mode: .all, promise: nil)
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
