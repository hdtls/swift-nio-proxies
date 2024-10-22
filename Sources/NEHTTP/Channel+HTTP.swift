//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2021 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import HTTPTypes
import NEAddressProcessing
import NIOCore
import NIOHTTP1
import NIOHTTPTypesHTTP1

extension Channel {

  /// Configure a HTTP tunnel for client.
  ///
  /// - Parameters:
  ///   - authenticationRequired: The flag whether the tunnel require authentication.
  ///   - passwordReference: The password reference for authentication.
  ///   - destinationAddress: The target address this tunnel work for.
  ///   - timeoutInterval: Amount of times that connection should timeout from now.
  ///   - position: The position in the pipeline whitch to insert the handlers.
  /// - Returns: An `EventLoopFuture<Void>` that completes when the channel is ready to negotiate.
  @preconcurrency public func configureHTTPTunnelPipeline(
    authenticationRequired: Bool = false,
    passwordReference: String = "",
    destinationAddress: Address,
    timeoutInterval: TimeAmount = .seconds(60),
    position: ChannelPipeline.Position = .last
  ) -> EventLoopFuture<Void> {
    _configureHTTPTunnelPipeline(
      authenticationRequired: authenticationRequired,
      passwordReference: passwordReference,
      destinationAddress: destinationAddress,
      timeoutInterval: timeoutInterval,
      position: position
    )
  }

  private func _configureHTTPTunnelPipeline(
    authenticationRequired: Bool = false,
    passwordReference: String = "",
    destinationAddress: Address,
    timeoutInterval: TimeAmount,
    position: ChannelPipeline.Position = .last
  ) -> EventLoopFuture<Void> {
    if eventLoop.inEventLoop {
      return eventLoop.makeCompletedFuture {
        try self.pipeline.syncOperations.configureHTTPTunnelPipeline(
          authenticationRequired: authenticationRequired,
          passwordReference: passwordReference,
          destinationAddress: destinationAddress,
          timeoutInterval: timeoutInterval,
          position: position
        )
      }
    } else {
      return eventLoop.submit {
        try self.pipeline.syncOperations.configureHTTPTunnelPipeline(
          authenticationRequired: authenticationRequired,
          passwordReference: passwordReference,
          destinationAddress: destinationAddress,
          timeoutInterval: timeoutInterval,
          position: position
        )
      }
    }
  }

  /// Configure a HTTP tunnel for server.
  ///
  /// - Parameters:
  ///   - authenticationRequired: The flag whether the tunnel require authentication.
  ///   - passwordReference: The password reference for authentication.
  ///   - position: The position in the pipeline whitch to insert the handlers.
  ///   - channelInitializer: The outbound channel initializer.
  /// - Returns: An `EventLoopFuture<EventLoopFuture<(any Channel, C>>` that completes when the channel is ready.
  @preconcurrency public func configureHTTPTunnelPipeline<C>(
    authenticationRequired: Bool = false,
    passwordReference: String = "",
    position: ChannelPipeline.Position = .last,
    channelInitializer: @escaping @Sendable (HTTPVersion, HTTPRequest) -> EventLoopFuture<
      (any Channel, C)
    >
  ) -> EventLoopFuture<EventLoopFuture<(any Channel, C)>> {
    _configureHTTPTunnelPipeline(
      authenticationRequired: authenticationRequired,
      passwordReference: passwordReference,
      position: position,
      channelInitializer: channelInitializer
    )
  }

  private func _configureHTTPTunnelPipeline<C>(
    authenticationRequired: Bool = false,
    passwordReference: String = "",
    position: ChannelPipeline.Position = .last,
    channelInitializer: @escaping @Sendable (HTTPVersion, HTTPRequest) -> EventLoopFuture<
      (any Channel, C)
    >
  ) -> EventLoopFuture<EventLoopFuture<(any Channel, C)>> {
    if eventLoop.inEventLoop {
      return eventLoop.makeCompletedFuture {
        try self.pipeline.syncOperations.configureHTTPTunnelPipeline(
          authenticationRequired: authenticationRequired,
          passwordReference: passwordReference,
          position: position,
          channelInitializer: channelInitializer
        )
      }
    } else {
      return eventLoop.submit {
        return try self.pipeline.syncOperations.configureHTTPTunnelPipeline(
          authenticationRequired: authenticationRequired,
          passwordReference: passwordReference,
          position: position,
          channelInitializer: channelInitializer
        )
      }
    }
  }
}

extension ChannelPipeline.SynchronousOperations {

  /// Configure a HTTP tunnel pipeline for client.
  ///
  /// - Parameters:
  ///   - authenticationRequired: The flag whether the tunnel require authentication.
  ///   - passwordReference: The password reference for authentication.
  ///   - destinationAddress: The target address this tunnel work for.
  ///   - timeoutInterval: Amount of times that connection should timeout from now.
  ///   - position: The position in the pipeline whitch to insert the handlers.
  public func configureHTTPTunnelPipeline(
    authenticationRequired: Bool = false,
    passwordReference: String,
    destinationAddress: Address,
    timeoutInterval: TimeAmount = .seconds(60),
    position: ChannelPipeline.Position = .last
  ) throws {
    eventLoop.assertInEventLoop()

    var handlers: [any RemovableChannelHandler] = [
      HTTPRequestEncoder(),
      ByteToMessageHandler(HTTPResponseDecoder()),
      HTTP1ToHTTPClientCodec(),
    ]

    let handshake = HTTPProxyClientHandler(
      passwordReference: passwordReference,
      authenticationRequired: authenticationRequired,
      destinationAddress: destinationAddress,
      additionalHTTPHandlers: handlers,
      timeoutInterval: timeoutInterval
    )

    handlers.append(handshake)
    try self.addHandlers(handlers, position: position)
  }

  /// Configure a HTTP tunnel pipeline for server.
  ///
  /// - Parameters:
  ///   - authenticationRequired: The flag whether the tunnel require authentication.
  ///   - passwordReference: The password reference for authentication.
  ///   - position: The position in the pipeline whitch to insert the handlers.
  ///   - channelInitializer: The outbound channel initializer.
  /// - Returns: An `EventLoopFuture<(any Channel, C>` that completes when the channel is ready.
  public func configureHTTPTunnelPipeline<C>(
    authenticationRequired: Bool = false,
    passwordReference: String,
    position: ChannelPipeline.Position = .last,
    channelInitializer: @escaping @Sendable (HTTPVersion, HTTPRequest) -> EventLoopFuture<
      (any Channel, C)
    >
  ) throws -> EventLoopFuture<(any Channel, C)> {
    eventLoop.assertInEventLoop()

    let additionalHTTPHandlers: [any RemovableChannelHandler] = [
      HTTPResponseEncoder(),
      ByteToMessageHandler(HTTPRequestDecoder()),
    ]

    let negotiationHandler = HTTPProxyServerHandler(
      passwordReference: passwordReference,
      authenticationRequired: authenticationRequired,
      additionalHTTPHandlers: additionalHTTPHandlers,
      channelInitializer: channelInitializer
    )

    var handlers = additionalHTTPHandlers
    handlers.append(negotiationHandler)

    try self.addHandlers(handlers, position: position)

    return negotiationHandler.negotiationResultFuture
  }
}
