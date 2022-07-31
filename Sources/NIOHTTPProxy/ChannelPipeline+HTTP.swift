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
import NIOHTTP1
import NIONetbotMisc

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
    ///   - channelInitializer: The outbound channel initializer used to initizlie outbound channel when receive proxy request.
    ///   - completion: The completion handler to use when handshake completed and outbound channel established.
    /// - Returns: An `EventLoopFuture` that will fire when the pipeline is configured.
    public func configureHTTPProxyServerPipeline(
        position: ChannelPipeline.Position = .last,
        username: String = "",
        passwordReference: String = "",
        authenticationRequired: Bool = false,
        channelInitializer: @escaping (Request) -> EventLoopFuture<Channel>,
        completion: @escaping (Request, Channel) -> EventLoopFuture<Void>
    ) -> EventLoopFuture<Void> {
        let execute = {
            try self.syncOperations.configureHTTPProxyServerPipeline(
                position: position,
                username: username,
                passwordReference: passwordReference,
                authenticationRequired: authenticationRequired,
                channelInitializer: channelInitializer,
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
    ///   - channelInitializer: The outbound channel initializer used to initizlie outbound channel when receive proxy request.
    ///   - completion: The completion handler to use when handshake completed and outbound channel established.
    /// - Throws: If the pipeline could not be configured.
    public func configureHTTPProxyServerPipeline(
        position: ChannelPipeline.Position = .last,
        username: String = "",
        passwordReference: String = "",
        authenticationRequired: Bool = false,
        channelInitializer: @escaping (Request) -> EventLoopFuture<Channel>,
        completion: @escaping (Request, Channel) -> EventLoopFuture<Void>
    ) throws {
        self.eventLoop.assertInEventLoop()

        let responseEncoder = HTTPResponseEncoder()
        let requestDecoder = HTTPRequestDecoder(leftOverBytesStrategy: .forwardBytes)
        let serverHandler = HTTPProxyServerHandler(
            username: username,
            passwordReference: passwordReference,
            authenticationRequired: authenticationRequired,
            channelInitializer: channelInitializer,
            completion: completion
        )

        let handlers: [RemovableChannelHandler] = [
            responseEncoder, ByteToMessageHandler(requestDecoder), serverHandler,
        ]
        try self.addHandlers(handlers, position: position)
    }
}
