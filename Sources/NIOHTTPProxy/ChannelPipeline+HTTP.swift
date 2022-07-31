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
import NIOHTTP1
import NIOHTTPCompression
import NIOHTTPMitM
import NIONetbotMisc
import NIOSSL

extension ChannelPipeline {

    /// Configure a `ChannelPipeline` for use as a HTTP proxy client.
    /// - Parameters:
    ///   - position: The position in the `ChannelPipeline` where to add the HTTP proxy client handlers. Defaults to `.last`.
    ///   - username: The username to use when authenticate this connection.
    ///   - passwordReference: The passwordReference to use when authenticate this connection.
    ///   - authenticationRequired: A boolean value to determinse whether HTTP proxy client should perform proxy authentication.
    ///   - preferHTTPTunneling: A boolean value use to determinse whether HTTP proxy client should use CONNECT method. Defaults to `true`.
    ///   - destinationAddress: The destination for proxy connection.
    /// - Returns: An `EventLoopFuture` that will fire when the pipeline is configured.
    public func addHTTPProxyClientHandlers(
        position: ChannelPipeline.Position = .last,
        username: String,
        passwordReference: String,
        authenticationRequired: Bool,
        preferHTTPTunneling: Bool = true,
        destinationAddress: NetAddress
    ) -> EventLoopFuture<Void> {
        let execute = {
            try self.syncOperations.addHTTPProxyClientHandlers(
                position: position,
                username: username,
                passwordReference: passwordReference,
                authenticationRequired: authenticationRequired,
                preferHTTPTunneling: preferHTTPTunneling,
                destinationAddress: destinationAddress
            )
        }

        return self.eventLoop.inEventLoop
            ? self.eventLoop.makeCompletedFuture(.init(catching: execute))
            : self.eventLoop.submit(execute)
    }

    /// Configure a `ChannelPipeline` for use as a HTTP proxy server.
    /// - Parameters:
    ///   - position: The position in the `ChannelPipeline` where to add the HTTP proxy client handlers. Defaults to `.last`.
    ///   - username: The username to use when authenticate this connection. Defaults to `""`.
    ///   - passwordReference: The passwordReference to use when authenticate this connection. Defaults to `""`.
    ///   - authenticationRequired: A boolean value to determinse whether HTTP proxy client should perform proxy authentication. Defaults to `false`.
    ///   - completion: The completion handler to use when handshake completed and prepare outbound channel.
    /// - Returns: An `EventLoopFuture` that will fire when the pipeline is configured.
    public func configureHTTPProxyServerPipeline(
        position: ChannelPipeline.Position = .last,
        username: String = "",
        passwordReference: String = "",
        authenticationRequired: Bool = false,
        enableHTTPCapture: Bool = false,
        enableMitM: Bool = false,
        mitmConfig: Configuration? = nil,
        completion: @escaping (Request) -> EventLoopFuture<Channel>
    ) -> EventLoopFuture<Void> {
        let execute = {
            try self.syncOperations.configureHTTPProxyServerPipeline(
                position: position,
                username: username,
                passwordReference: passwordReference,
                authenticationRequired: authenticationRequired,
                enableHTTPCapture: enableHTTPCapture,
                enableMitM: enableMitM,
                mitmConfig: mitmConfig,
                completion: completion
            )
        }

        return self.eventLoop.inEventLoop
            ? self.eventLoop.makeCompletedFuture(.init(catching: execute))
            : self.eventLoop.submit(execute)
    }
}

extension ChannelPipeline.SynchronousOperations {

    /// Configure a `ChannelPipeline` for use as a HTTP proxy client.
    /// - Parameters:
    ///   - position: The position in the `ChannelPipeline` where to add the HTTP proxy client handlers. Defaults to `.last`.
    ///   - username: The username to use when authenticate this connection.
    ///   - passwordReference: The passwordReference to use when authenticate this connection.
    ///   - authenticationRequired: A boolean value to determinse whether HTTP proxy client should perform proxy authentication.
    ///   - preferHTTPTunneling: A boolean value use to determinse whether HTTP proxy client should use CONNECT method. Defaults to `true.`
    ///   - destinationAddress: The destination for proxy connection.
    /// - Throws: If the pipeline could not be configured.
    public func addHTTPProxyClientHandlers(
        position: ChannelPipeline.Position = .last,
        username: String,
        passwordReference: String,
        authenticationRequired: Bool,
        preferHTTPTunneling: Bool = true,
        destinationAddress: NetAddress
    ) throws {
        eventLoop.assertInEventLoop()
        let handlers: [ChannelHandler] = [
            HTTP1ClientCONNECTTunnelHandler(
                username: username,
                passwordReference: passwordReference,
                authenticationRequired: authenticationRequired,
                preferHTTPTunneling: preferHTTPTunneling,
                destinationAddress: destinationAddress
            )
        ]
        try self.addHTTPClientHandlers()
        try self.addHandlers(handlers, position: position)
    }

    /// Configure a `ChannelPipeline` for use as a HTTP proxy server.
    /// - Parameters:
    ///   - position: The position in the `ChannelPipeline` where to add the HTTP proxy client handlers. Defaults to `.last`.
    ///   - username: The username to use when authenticate this connection. Defaults to `""`.
    ///   - passwordReference: The passwordReference to use when authenticate this connection. Defaults to `""`.
    ///   - authenticationRequired: A boolean value to determinse whether HTTP proxy client should perform proxy authentication. Defaults to `false`.
    ///   - completion: The completion handler to use when handshake completed and prepare outbound channel.
    /// - Throws: If the pipeline could not be configured.
    public func configureHTTPProxyServerPipeline(
        position: ChannelPipeline.Position = .last,
        username: String = "",
        passwordReference: String = "",
        authenticationRequired: Bool = false,
        enableHTTPCapture: Bool = false,
        enableMitM: Bool = false,
        mitmConfig: Configuration? = nil,
        completion: @escaping (Request) -> EventLoopFuture<Channel>
    ) throws {
        self.eventLoop.assertInEventLoop()

        let responseEncoder = HTTPResponseEncoder()
        let requestDecoder = HTTPRequestDecoder(leftOverBytesStrategy: .forwardBytes)
        let serverHandler = HTTPProxyServerHandler(
            username: username,
            passwordReference: passwordReference,
            authenticationRequired: authenticationRequired,
            channelInitializer: completion
        ) { req, peer in
            try self.addHandler(
                NIOSSLDetectionHandler { result, channel -> EventLoopFuture<Void> in
                    let promise = channel.eventLoop.makePromise(of: Void.self)
                    promise.completeWithTask {
                        let detectHandler = try await channel.pipeline.handler(
                            type: NIOSSLDetectionHandler.self
                        ).get()

                        // Those handlers will be added to `self` to enable HTTP capture for request.
                        let handlers0: [ChannelHandler] = [
                            HTTPResponseCompressor(),
                            HTTPCaptureHandler<HTTPRequestHead>(
                                logger: Logger(label: "http.capture")
                            ),
                            HTTPIOTransformer<HTTPRequestHead>(),
                        ]

                        // Those handlers will be added to the channel to enable HTTP capture for response.
                        let handlers1: [ChannelHandler] = [
                            NIOHTTPResponseDecompressor(limit: .none),
                            HTTPCaptureHandler<HTTPResponseHead>(
                                logger: Logger(label: "http.capture")
                            ),
                            HTTPIOTransformer<HTTPResponseHead>(),
                        ]

                        // If detect SSL handshake then setup SSL pipeline to decode SSL stream.
                        guard result else {
                            guard enableHTTPCapture else {
                                return
                            }

                            try await channel.pipeline.addHandlers(
                                handlers0,
                                position: .after(detectHandler)
                            )
                            try await peer.pipeline.addHandlers(handlers1, position: .first)
                            return
                        }

                        guard let base64EncodedP12String = mitmConfig?.base64EncodedP12String else {
                            // To enable the HTTP MitM feature, you must provide the corresponding configuration.
                            throw NIOSSLError.failedToLoadCertificate
                        }

                        let store = try CertificateStore(
                            passphrase: mitmConfig?.passphrase,
                            base64EncodedP12String: base64EncodedP12String
                        )

                        await store.setUpMitMHosts(mitmConfig?.hostnames ?? [])

                        guard
                            let p12 = try await store.certificate(identifiedBy: req.serverHostname)
                        else {
                            return
                        }

                        let certificateChain = p12.certificateChain.map(
                            NIOSSLCertificateSource.certificate
                        )
                        let privateKey = NIOSSLPrivateKeySource.privateKey(p12.privateKey)
                        var configuration = TLSConfiguration.makeServerConfiguration(
                            certificateChain: certificateChain,
                            privateKey: privateKey
                        )
                        configuration.certificateVerification =
                            mitmConfig?.skipCertificateVerification == true
                            ? .none : .fullVerification
                        var sslContext = try NIOSSLContext(configuration: configuration)
                        var handlers: [ChannelHandler] = [
                            NIOSSLServerHandler(context: sslContext),
                            HTTPResponseEncoder(),
                            ByteToMessageHandler(HTTPRequestDecoder()),
                        ]
                        if enableHTTPCapture {
                            handlers.append(contentsOf: handlers0)
                        }
                        try await channel.pipeline.addHandlers(
                            handlers,
                            position: .after(detectHandler)
                        )

                        // Peer channel pipeline setup.
                        configuration = TLSConfiguration.makeClientConfiguration()
                        sslContext = try NIOSSLContext(configuration: configuration)
                        let sslHandler = try NIOSSLClientHandler(
                            context: sslContext,
                            serverHostname: req.serverHostname
                        )
                        handlers = [
                            sslHandler,
                            HTTPRequestEncoder(),
                            ByteToMessageHandler(HTTPResponseDecoder()),
                        ]
                        if enableHTTPCapture {
                            handlers.append(contentsOf: handlers1)
                        }
                        try await peer.pipeline.addHandlers(handlers, position: .first)
                    }
                    return promise.futureResult
                }
            )
        }

        let handlers: [RemovableChannelHandler] = [
            responseEncoder, ByteToMessageHandler(requestDecoder), serverHandler,
        ]
        try self.addHandlers(handlers, position: position)
    }
}
