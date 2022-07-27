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

import NIOCore

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
        ) { req, channel in
            let serverHostname = req.serverHostname

            let enableHTTPCapture0 = {
                // Those handlers will be added to `self` to enable HTTP capture for request.
                let handlers0: [ChannelHandler] = [
                    HTTPResponseCompressor(),
                    HTTPCaptureHandler<HTTPRequestHead>(logger: Logger(label: "http.capture")),
                    HTTPIOTransformer<HTTPRequestHead>(),
                ]

                // Those handlers will be added to the channel to enable HTTP capture for response.
                let handlers1: [ChannelHandler] = [
                    NIOHTTPResponseDecompressor(limit: .none),
                    HTTPCaptureHandler<HTTPResponseHead>(logger: Logger(label: "http.capture")),
                    HTTPIOTransformer<HTTPResponseHead>(),
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
                return serverHostname.contains(
                    $0.key.suffix(from: $0.key.index($0.key.startIndex, offsetBy: 2))
                )
            }?.value

            guard let p12 = p12 else {
                return
            }

            let certificateChain = p12.certificateChain.map(NIOSSLCertificateSource.certificate)
            let privateKey = NIOSSLPrivateKeySource.privateKey(p12.privateKey)

            try self.configureSSLServerHandlers(
                certificateChain: certificateChain,
                privateKey: privateKey
            )
            try self.configureHTTPServerPipeline(
                withPipeliningAssistance: false,
                withErrorHandling: false
            )

            // Peer channel pipeline setup.
            try channel.pipeline.syncOperations.addSSLClientHandlers(serverHostname: serverHostname)
            try channel.pipeline.syncOperations.addHTTPClientHandlers()

            try enableHTTPCapture0()
        }

        let handlers: [RemovableChannelHandler] = [
            responseEncoder, ByteToMessageHandler(requestDecoder), serverHandler,  // MITM
        ]

        try self.addHandlers(handlers, position: position)
    }
}
