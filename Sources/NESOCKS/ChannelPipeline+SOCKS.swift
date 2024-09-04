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

public enum NESOCKSMode: Sendable {
  case client
  case server
}

extension Channel {

  /// Configure a SOCKS5 proxy channel.
  ///
  /// - Parameters:
  ///   - mode: The mode this pipeline will operate in, server or client.
  ///   - username: The username to use when authenticate this connection. Defaults to `""`.
  ///   - passwordReference: The passwordReference to use when authenticate this connection. Defaults to `""`.
  ///   - authenticationRequired: A boolean value to determinse whether SOCKS proxy client should perform proxy authentication. Defaults to `false`.
  ///   - position: The position in the `ChannelPipeline` where to add the SOCKS proxy server handlers. Defaults to `.last`.
  ///   - completion: The completion handler to use when handshake completed and outbound channel established.
  ///       this completion pass request info, server channel and outbound client channel and returns `EventLoopFuture<Void>`.
  /// - Returns: An `EventLoopFuture<Void>` that completes when the channel is ready to negotiate.
  public func configureSOCKS5Pipeline(
    mode: NESOCKSMode,
    username: String = "",
    passwordReference: String = "",
    authenticationRequired: Bool = false,
    destinationAddress: NWEndpoint? = nil,
    position: ChannelPipeline.Position = .last,
    completion: (@Sendable (NWEndpoint) -> EventLoopFuture<Void>)? = nil
  ) -> EventLoopFuture<Void> {
    let position = NIOLoopBound(position, eventLoop: eventLoop)

    if eventLoop.inEventLoop {
      return eventLoop.makeCompletedFuture {
        try self.pipeline.syncOperations.configureSOCKS5Pipeline(
          mode: mode,
          username: username,
          passwordReference: passwordReference,
          authenticationRequired: authenticationRequired,
          destinationAddress: destinationAddress,
          position: position.value,
          completion: completion
        )
      }
    } else {
      return eventLoop.submit {
        try self.pipeline.syncOperations.configureSOCKS5Pipeline(
          mode: mode,
          username: username,
          passwordReference: passwordReference,
          authenticationRequired: authenticationRequired,
          destinationAddress: destinationAddress,
          position: position.value,
          completion: completion
        )
      }
    }
  }
}

extension ChannelPipeline.SynchronousOperations {

  /// Configure a SOCKS5 proxy channel pipeline.
  ///
  /// - Parameters:
  ///   - mode: The mode this pipeline will operate in, server or client.
  ///   - username: The username to use when authenticate this connection. Defaults to `""`.
  ///   - passwordReference: The passwordReference to use when authenticate this connection. Defaults to `""`.
  ///   - authenticationRequired: A boolean value to determinse whether SOCKS proxy client should perform proxy authentication. Defaults to `false`.
  ///   - position: The position in the `ChannelPipeline` where to add the SOCKS proxy server handlers. Defaults to `.last`.
  ///   - completion: The completion handler to use when handshake completed and outbound channel established.
  ///       this completion pass request info, server channel and outbound client channel and returns `EventLoopFuture<Void>`.
  /// - Throws: If the pipeline could not be configured.
  public func configureSOCKS5Pipeline(
    mode: NESOCKSMode,
    username: String = "",
    passwordReference: String = "",
    authenticationRequired: Bool = false,
    destinationAddress: NWEndpoint? = nil,
    position: ChannelPipeline.Position = .last,
    completion: (@Sendable (NWEndpoint) -> EventLoopFuture<Void>)? = nil
  ) throws {
    self.eventLoop.assertInEventLoop()

    switch mode {
    case .client:
      guard let destinationAddress else {
        fatalError("Missing required destination address.")
      }
      let handler = SOCKS5ClientHandler(
        username: username,
        passwordReference: passwordReference,
        authenticationRequired: authenticationRequired,
        destinationAddress: destinationAddress
      )

      try addHandler(handler)
    case .server:
      guard let completion else {
        fatalError("Missing required completion handler.")
      }
      let handler = SOCKS5ServerHandler(
        username: username,
        passwordReference: passwordReference,
        authenticationRequired: authenticationRequired,
        completion: completion
      )

      try self.addHandler(handler, position: position)
    }
  }
}
