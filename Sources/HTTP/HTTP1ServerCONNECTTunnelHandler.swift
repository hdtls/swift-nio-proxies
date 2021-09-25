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
    public let isMitMEnabled: Bool = true
    
    /// Enable this to capture http body.
    public let isHTTPCaptureEnabled: Bool = true
    
    public let sslDecConfig: SSLDecryptionConfiguration = .init(skipServerCertificateVerification: true, hostnames: ["*.baidu.com", "*.ietf.org"], base64EncodedP12String: "", passphrase: "")
    
    public class SSLDecryptionConfiguration: Codable {
        public var skipServerCertificateVerification: Bool
        public var hostnames: [String] = [] {
            didSet {
                let pool = self.pool
                self.pool.removeAll()
                
                guard !hostnames.isEmpty else {
                    return
                }
                
                do {
                    let bundle = try boringSSLParseBase64EncodedPKCS12BundleString(
                        passphrase: passphrase,
                        base64EncodedString: base64EncodedP12String
                    )
                    
                    try self.hostnames.forEach { hostname in
                        guard pool[hostname] == nil else {
                            self.pool[hostname] = pool[hostname]
                            return
                        }
                        
                        let p12 = try boringSSLSelfSignedPKCS12Bundle(
                            passphrase: passphrase,
                            certificate: bundle.certificateChain[0],
                            privateKey: bundle.privateKey, hostname: hostname
                        )
                        
                        self.pool[hostname] = try NIOSSLPKCS12Bundle(
                            buffer: boringSSLPKCS12BundleDERBytes(p12),
                            passphrase: Array(passphrase.utf8)
                        )
                    }
                } catch {
                    preconditionFailure("Failed to sign ssl server certificate for sites \(hostnames.joined(separator: ",")).")
                }
            }
        }
        public var base64EncodedP12String: String
        public var passphrase: String
        
        public var pool: [String : NIOSSLPKCS12Bundle] = [:]
        
        enum CodingKeys: String, CodingKey {
            case skipServerCertificateVerification
            case hostnames
            case base64EncodedP12String
            case passphrase
        }
        
        public init(skipServerCertificateVerification: Bool,
                    hostnames: [String],
                    base64EncodedP12String: String,
                    passphrase: String) {
            self.skipServerCertificateVerification = skipServerCertificateVerification
            // Filter hostname if host contains in a wildcard host. e.g. apple.com and *.apple.com
            self.passphrase = "EMMX3K37"
            self.base64EncodedP12String = "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"
        
            ({ self.hostnames = hostnames })()
        }
    }
    
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
        
        let passingTests = sslDecConfig.hostnames.contains { hostname in
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
                
                var filtered: [String : NIOSSLPKCS12Bundle]?
                
                // Only filter PKCS#12 bundle when `isMitMEnabled` set to true.
                if self.isMitMEnabled {
                    filtered = self.sslDecConfig.pool.filter {
                        if $0.key.hasPrefix("*") {
                            return serverHostname.contains($0.key.dropFirst())
                        }
                        return $0.key == serverHostname
                    }
                }
                
                guard self.isMitMEnabled, let bundle = filtered?.first?.value else {
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
