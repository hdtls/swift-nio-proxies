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

import HTTPTypes
import NIOCore
import NIOHTTP1
import _NELinux

extension ChannelPipeline {

  /// Configure a `ChannelPipeline` for use as a HTTP proxy client.
  /// - Parameters:
  ///   - position: The position in the `ChannelPipeline` where to add the HTTP proxy client handlers. Defaults to `.last`.
  ///   - passwordReference: The credentials to use when authenticate this connection.
  ///   - authenticationRequired: A boolean value to determinse whether HTTP proxy client should perform proxy authentication.
  ///   - preferHTTPTunneling: A boolean value use to determinse whether HTTP proxy client should use CONNECT method. Defaults to `true`.
  ///   - destinationAddress: The destination for proxy connection.
  /// - Returns: An `EventLoopFuture` that will fire when the pipeline is configured.
  public func addHTTPProxyClientHandlers(
    position: ChannelPipeline.Position = .last,
    passwordReference: String,
    authenticationRequired: Bool,
    preferHTTPTunneling: Bool = true,
    destinationAddress: NWEndpoint
  ) -> EventLoopFuture<Void> {

    guard eventLoop.inEventLoop else {
      return eventLoop.submit {
        try self.syncOperations.addHTTPProxyClientHandlers(
          position: position,
          passwordReference: passwordReference,
          authenticationRequired: authenticationRequired,
          preferHTTPTunneling: preferHTTPTunneling,
          destinationAddress: destinationAddress
        )
      }
    }

    return eventLoop.makeCompletedFuture {
      try self.syncOperations.addHTTPProxyClientHandlers(
        position: position,
        passwordReference: passwordReference,
        authenticationRequired: authenticationRequired,
        preferHTTPTunneling: preferHTTPTunneling,
        destinationAddress: destinationAddress
      )
    }
  }

  /// Configure a `ChannelPipeline` for use as a HTTP proxy server.
  /// - Parameters:
  ///   - position: The position in the `ChannelPipeline` where to add the HTTP proxy server handlers. Defaults to `.last`.
  ///   - passwordReference: The credentials to use when authenticate this connection. Defaults to `""`.
  ///   - authenticationRequired: A boolean value to determinse whether HTTP proxy server should perform proxy authentication. Defaults to `false`.
  ///   - completion: The completion handler to use when handshake completed and outbound channel established.
  ///       this completion pass request info, server channel and outbound client channel and returns `EventLoopFuture<Void>`.
  /// - Returns: An `EventLoopFuture` that will fire when the pipeline is configured.
  public func configureHTTPProxyServerPipeline(
    position: ChannelPipeline.Position = .last,
    passwordReference: String = "",
    authenticationRequired: Bool = false,
    completion: @escaping @Sendable (HTTPVersion, HTTPRequest) -> EventLoopFuture<Void>
  ) -> EventLoopFuture<Void> {

    guard eventLoop.inEventLoop else {
      return eventLoop.submit {
        try self.syncOperations.configureHTTPProxyServerPipeline(
          position: position,
          passwordReference: passwordReference,
          authenticationRequired: authenticationRequired,
          completion: completion
        )
      }
    }

    return eventLoop.makeCompletedFuture {
      try self.syncOperations.configureHTTPProxyServerPipeline(
        position: position,
        passwordReference: passwordReference,
        authenticationRequired: authenticationRequired,
        completion: completion
      )
    }
  }
}

extension ChannelPipeline.SynchronousOperations {

  /// Configure a `ChannelPipeline` for use as a HTTP proxy client.
  /// - Parameters:
  ///   - position: The position in the `ChannelPipeline` where to add the HTTP proxy client handlers. Defaults to `.last`.
  ///   - passwordReference: The credentials to use when authenticate this connection.
  ///   - authenticationRequired: A boolean value to determinse whether HTTP proxy client should perform proxy authentication.
  ///   - preferHTTPTunneling: A boolean value use to determinse whether HTTP proxy client should use CONNECT method. Defaults to `true.`
  ///   - destinationAddress: The destination for proxy connection.
  /// - Throws: If the pipeline could not be configured.
  public func addHTTPProxyClientHandlers(
    position: ChannelPipeline.Position = .last,
    passwordReference: String,
    authenticationRequired: Bool,
    preferHTTPTunneling: Bool = true,
    destinationAddress: NWEndpoint
  ) throws {
    eventLoop.assertInEventLoop()
    let handlers: [ChannelHandler] = [
      HTTPProxyClientHandler(
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
  ///   - position: The position in the `ChannelPipeline` where to add the HTTP proxy server handlers. Defaults to `.last`.
  ///   - passwordReference: The credentials to use when authenticate this connection. Defaults to `""`.
  ///   - authenticationRequired: A boolean value to determinse whether HTTP proxy server should perform proxy authentication. Defaults to `false`.
  ///   - completion: The completion handler to use when handshake completed and outbound channel established.
  ///       this completion pass request info, server channel and outbound client channel and returns `EventLoopFuture<Void>`.
  /// - Throws: If the pipeline could not be configured.
  public func configureHTTPProxyServerPipeline(
    position: ChannelPipeline.Position = .last,
    passwordReference: String = "",
    authenticationRequired: Bool = false,
    completion: @escaping @Sendable (HTTPVersion, HTTPRequest) -> EventLoopFuture<Void>
  ) throws {
    self.eventLoop.assertInEventLoop()

    let responseEncoder = HTTPResponseEncoder()
    let requestDecoder = HTTPRequestDecoder(leftOverBytesStrategy: .forwardBytes)
    let serverHandler = HTTPProxyRecipientHandelr(
      passwordReference: passwordReference,
      authenticationRequired: authenticationRequired,
      completion: completion
    )

    let handlers: [RemovableChannelHandler] = [
      responseEncoder, ByteToMessageHandler(requestDecoder), serverHandler,
    ]
    try self.addHandlers(handlers, position: position)
  }
}
