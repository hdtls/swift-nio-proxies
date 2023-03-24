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

@_exported import NEMisc
@_exported import NIOCore

extension ChannelPipeline {

  /// Configure a `ChannelPipeline` for use as a SOCKS client.
  /// - Parameters:
  ///   - position: The position in the `ChannelPipeline` where to add the SOCKS proxy client handlers. Defaults to `.last`.
  ///   - username: The username to use when authenticate this connection.
  ///   - passwordReference: The passwordReference to use when authenticate this connection.
  ///   - authenticationRequired: A boolean value to determinse whether SOCKS proxy client should perform proxy authentication.
  ///   - destinationAddress: The destination for proxy connection.
  /// - Returns: An `EventLoopFuture` that will fire when the pipeline is configured.
  public func addSOCKSClientHandlers(
    position: Position = .last,
    username: String,
    passwordReference: String,
    authenticationRequired: Bool,
    destinationAddress: NetAddress
  ) -> EventLoopFuture<Void> {

    guard eventLoop.inEventLoop else {
      return eventLoop.submit {
        try self.syncOperations.addSOCKSClientHandlers(
          position: position,
          username: username,
          passwordReference: passwordReference,
          authenticationRequired: authenticationRequired,
          destinationAddress: destinationAddress
        )
      }
    }

    return eventLoop.makeCompletedFuture {
      try self.syncOperations.addSOCKSClientHandlers(
        position: position,
        username: username,
        passwordReference: passwordReference,
        authenticationRequired: authenticationRequired,
        destinationAddress: destinationAddress
      )
    }
  }

  #if swift(>=5.7)
  /// Configure a `ChannelPipeline` for use as a SOCKS proxy server.
  /// - Parameters:
  ///   - position: The position in the `ChannelPipeline` where to add the SOCKS proxy server handlers. Defaults to `.last`.
  ///   - username: The username to use when authenticate this connection. Defaults to `""`.
  ///   - passwordReference: The passwordReference to use when authenticate this connection. Defaults to `""`.
  ///   - authenticationRequired: A boolean value to determinse whether SOCKS proxy client should perform proxy authentication. Defaults to `false`.
  ///   - channelInitializer: The outbound channel initializer used to initizlie outbound channel when receive proxy request.
  ///       this initializer pass proxy request info and returns initialized outbound channel.
  ///   - completion: The completion handler to use when handshake completed and outbound channel established.
  ///       this completion pass request info, server channel and outbound client channel and returns `EventLoopFuture<Void>`.
  /// - Returns: An `EventLoopFuture` that will fire when the pipeline is configured.
  @preconcurrency
  public func configureSOCKSServerPipeline(
    position: ChannelPipeline.Position = .last,
    username: String = "",
    passwordReference: String = "",
    authenticationRequired: Bool = false,
    channelInitializer: @escaping @Sendable (RequestInfo) -> EventLoopFuture<Channel>,
    completion: @escaping @Sendable (RequestInfo, Channel, Channel) -> EventLoopFuture<Void>
  ) -> EventLoopFuture<Void> {

    guard eventLoop.inEventLoop else {
      return eventLoop.submit {
        try self.syncOperations.configureSOCKSServerPipeline(
          position: position,
          username: username,
          passwordReference: passwordReference,
          authenticationRequired: authenticationRequired,
          channelInitializer: channelInitializer,
          completion: completion
        )
      }
    }

    return eventLoop.makeCompletedFuture {
      try self.syncOperations.configureSOCKSServerPipeline(
        position: position,
        username: username,
        passwordReference: passwordReference,
        authenticationRequired: authenticationRequired,
        channelInitializer: channelInitializer,
        completion: completion
      )
    }
  }
  #else
  /// Configure a `ChannelPipeline` for use as a SOCKS proxy server.
  /// - Parameters:
  ///   - position: The position in the `ChannelPipeline` where to add the SOCKS proxy server handlers. Defaults to `.last`.
  ///   - username: The username to use when authenticate this connection. Defaults to `""`.
  ///   - passwordReference: The passwordReference to use when authenticate this connection. Defaults to `""`.
  ///   - authenticationRequired: A boolean value to determinse whether SOCKS proxy client should perform proxy authentication. Defaults to `false`.
  ///   - channelInitializer: The outbound channel initializer used to initizlie outbound channel when receive proxy request.
  ///       this initializer pass proxy request info and returns initialized outbound channel.
  ///   - completion: The completion handler to use when handshake completed and outbound channel established.
  ///       this completion pass request info, server channel and outbound client channel and returns `EventLoopFuture<Void>`.
  /// - Returns: An `EventLoopFuture` that will fire when the pipeline is configured.
  public func configureSOCKSServerPipeline(
    position: ChannelPipeline.Position = .last,
    username: String = "",
    passwordReference: String = "",
    authenticationRequired: Bool = false,
    channelInitializer: @escaping (RequestInfo) -> EventLoopFuture<Channel>,
    completion: @escaping (RequestInfo, Channel, Channel) -> EventLoopFuture<Void>
  ) -> EventLoopFuture<Void> {

    guard eventLoop.inEventLoop else {
      return eventLoop.submit {
        try self.syncOperations.configureSOCKSServerPipeline(
          position: position,
          username: username,
          passwordReference: passwordReference,
          authenticationRequired: authenticationRequired,
          channelInitializer: channelInitializer,
          completion: completion
        )
      }
    }

    return eventLoop.makeCompletedFuture {
      try self.syncOperations.configureSOCKSServerPipeline(
        position: position,
        username: username,
        passwordReference: passwordReference,
        authenticationRequired: authenticationRequired,
        channelInitializer: channelInitializer,
        completion: completion
      )
    }
  }
  #endif
}

extension ChannelPipeline.SynchronousOperations {

  /// Configure a `ChannelPipeline` for use as a SOCKS client.
  /// - Parameters:
  ///   - position: The position in the `ChannelPipeline` where to add the SOCKS proxy client handlers. Defaults to `.last`.
  ///   - username: The username to use when authenticate this connection.
  ///   - passwordReference: The passwordReference to use when authenticate this connection.
  ///   - authenticationRequired: A boolean value to determinse whether SOCKS proxy client should perform proxy authentication.
  ///   - destinationAddress: The destination for proxy connection.
  /// - Throws: If the pipeline could not be configured.
  public func addSOCKSClientHandlers(
    position: ChannelPipeline.Position = .last,
    username: String,
    passwordReference: String,
    authenticationRequired: Bool,
    destinationAddress: NetAddress
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

  /// Configure a `ChannelPipeline` for use as a SOCKS proxy server.
  /// - Parameters:
  ///   - position: The position in the `ChannelPipeline` where to add the SOCKS proxy server handlers. Defaults to `.last`.
  ///   - username: The username to use when authenticate this connection. Defaults to `""`.
  ///   - passwordReference: The passwordReference to use when authenticate this connection. Defaults to `""`.
  ///   - authenticationRequired: A boolean value to determinse whether SOCKS proxy client should perform proxy authentication. Defaults to `false`.
  ///   - channelInitializer: The outbound channel initializer used to initizlie outbound channel when receive proxy request.
  ///       this initializer pass proxy request info and returns initialized outbound channel.
  ///   - completion: The completion handler to use when handshake completed and outbound channel established.
  ///       this completion pass request info, server channel and outbound client channel and returns `EventLoopFuture<Void>`.
  /// - Throws: If the pipeline could not be configured.
  public func configureSOCKSServerPipeline(
    position: ChannelPipeline.Position = .last,
    username: String = "",
    passwordReference: String = "",
    authenticationRequired: Bool = false,
    channelInitializer: @escaping (RequestInfo) -> EventLoopFuture<Channel>,
    completion: @escaping (RequestInfo, Channel, Channel) -> EventLoopFuture<Void>
  ) throws {
    self.eventLoop.assertInEventLoop()

    let handler = SOCKS5ServerHandler(
      username: username,
      passwordReference: passwordReference,
      authenticationRequired: authenticationRequired,
      channelInitializer: channelInitializer,
      completion: completion
    )

    try self.addHandler(handler, position: position)
  }
}
