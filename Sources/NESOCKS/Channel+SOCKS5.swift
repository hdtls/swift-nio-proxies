//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2021 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore
import _NELinux

extension Channel {

  /// Configure a SOCKS5 proxy channel for client.
  ///
  /// - Parameters:
  ///   - username: The username to use when authenticate this connection. Defaults to `""`.
  ///   - passwordReference: The passwordReference to use when authenticate this connection. Defaults to `""`.
  ///   - authenticationRequired: A boolean value to determine whether SOCKS proxy client should perform proxy authentication. Defaults to `false`.
  ///   - destinationAddress: The target address this tunnel work for.
  ///   - position: The position in the `ChannelPipeline` where to add the SOCKS proxy server handlers. Defaults to `.last`.
  /// - Returns: An `EventLoopFuture<Void>` that completes when the channel is ready.
  public func configureSOCKS5Pipeline(
    username: String = "",
    passwordReference: String = "",
    authenticationRequired: Bool = false,
    destinationAddress: NWEndpoint,
    position: ChannelPipeline.Position = .last
  ) -> EventLoopFuture<Void> {
    if eventLoop.inEventLoop {
      return eventLoop.makeCompletedFuture {
        try self.pipeline.syncOperations.configureSOCKS5Pipeline(
          username: username,
          passwordReference: passwordReference,
          authenticationRequired: authenticationRequired,
          destinationAddress: destinationAddress,
          position: position
        )
      }
    } else {
      return eventLoop.submit {
        try self.pipeline.syncOperations.configureSOCKS5Pipeline(
          username: username,
          passwordReference: passwordReference,
          authenticationRequired: authenticationRequired,
          destinationAddress: destinationAddress,
          position: position
        )
      }
    }
  }

  /// Configure a SOCKS5 proxy channel for server.
  ///
  /// - Parameters:
  ///   - username: The username to use when authenticate this connection. Defaults to `""`.
  ///   - passwordReference: The passwordReference to use when authenticate this connection. Defaults to `""`.
  ///   - authenticationRequired: A boolean value to determinse whether SOCKS proxy client should perform proxy authentication. Defaults to `false`.
  ///   - position: The position in the `ChannelPipeline` where to add the SOCKS proxy server handlers. Defaults to `.last`.
  ///   - channelInitializer: The outbound channel initialzier to use to create channel to proxy server.
  ///       this channel initializer pass request info and returns `EventLoopFuture<any Channel, C>`.
  /// - Returns: An `EventLoopFuture<EventLoopFuture<(any Channel, C>>` that completes when the channel is ready.
  public func configureSOCKS5Pipeline<C>(
    username: String = "",
    passwordReference: String = "",
    authenticationRequired: Bool = false,
    position: ChannelPipeline.Position = .last,
    channelInitializer: @escaping @Sendable (NWEndpoint) -> EventLoopFuture<(any Channel, C)>
  ) -> EventLoopFuture<EventLoopFuture<(any Channel, C)>> {
    if eventLoop.inEventLoop {
      return eventLoop.makeCompletedFuture {
        try self.pipeline.syncOperations.configureSOCKS5Pipeline(
          username: username,
          passwordReference: passwordReference,
          authenticationRequired: authenticationRequired,
          position: position,
          channelInitializer: channelInitializer
        )
      }
    } else {
      return eventLoop.submit {
        try self.pipeline.syncOperations.configureSOCKS5Pipeline(
          username: username,
          passwordReference: passwordReference,
          authenticationRequired: authenticationRequired,
          position: position,
          channelInitializer: channelInitializer
        )
      }
    }
  }
}

extension ChannelPipeline.SynchronousOperations {

  /// Configure a SOCKS5 proxy channel pipeline for client.
  ///
  /// - Parameters:
  ///   - mode: The mode this pipeline will operate in, server or client.
  ///   - username: The username to use when authenticate this connection. Defaults to `""`.
  ///   - passwordReference: The passwordReference to use when authenticate this connection. Defaults to `""`.
  ///   - authenticationRequired: A boolean value to determinse whether SOCKS proxy client should perform proxy authentication. Defaults to `false`.
  ///   - destinationAddress: The target address this tunnel work for.
  ///   - position: The position in the `ChannelPipeline` where to add the SOCKS proxy server handlers. Defaults to `.last`.
  public func configureSOCKS5Pipeline(
    username: String = "",
    passwordReference: String = "",
    authenticationRequired: Bool = false,
    destinationAddress: NWEndpoint,
    position: ChannelPipeline.Position = .last
  ) throws {
    eventLoop.assertInEventLoop()

    let handler = SOCKS5ClientHandler(
      username: username,
      passwordReference: passwordReference,
      authenticationRequired: authenticationRequired,
      destinationAddress: destinationAddress
    )

    try addHandler(handler)
  }

  /// Configure a SOCKS5 proxy channel pipeline for server.
  ///
  /// - Parameters:
  ///   - username: The username to use when authenticate this connection. Defaults to `""`.
  ///   - passwordReference: The passwordReference to use when authenticate this connection. Defaults to `""`.
  ///   - authenticationRequired: A boolean value to determinse whether SOCKS proxy client should perform proxy authentication. Defaults to `false`.
  ///   - position: The position in the `ChannelPipeline` where to add the SOCKS proxy server handlers. Defaults to `.last`.
  ///   - channelInitializer: The outbound channel initialzier to use to create channel to proxy server.
  ///       this channel initializer pass request info and returns `EventLoopFuture<any Channel, C>`.
  /// - Returns: An `EventLoopFuture<EventLoopFuture<(any Channel, C>>` that completes when the channel is ready.
  public func configureSOCKS5Pipeline<C>(
    username: String = "",
    passwordReference: String = "",
    authenticationRequired: Bool = false,
    position: ChannelPipeline.Position = .last,
    channelInitializer: @escaping @Sendable (NWEndpoint) -> EventLoopFuture<(any Channel, C)>
  ) throws -> EventLoopFuture<(any Channel, C)> {
    eventLoop.assertInEventLoop()

    let negotiationHandler = SOCKS5ServerHandler(
      username: username,
      passwordReference: passwordReference,
      authenticationRequired: authenticationRequired,
      channelInitializer: channelInitializer
    )

    try self.addHandler(negotiationHandler, position: position)

    return negotiationHandler.negotiationResultFuture
  }
}
