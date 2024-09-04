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

public enum NEHTTPMode: Sendable {
  case client
  case server
}

extension Channel {

  /// Configure a HTTP tunnel.
  ///
  /// - Parameters:
  ///   - mode: The mode this pipeline will operate in, server or client.
  ///   - authenticationRequired: The flag whether the tunnel require authentication.
  ///   - passwordReference: The password reference for authentication.
  ///   - destinationAddress: The target address this tunnel work for. Client only.
  ///   - position: The position in the pipeline whitch to insert the handlers.
  ///   - completion: The completion handler when negotation complete. Server only.
  /// - Returns: An `EventLoopFuture<Void>` that completes when the channel is ready to negotiate.
  public func configureHTTPTunnelPipeline(
    mode: NEHTTPMode,
    authenticationRequired: Bool = false,
    passwordReference: String = "",
    destinationAddress: NWEndpoint? = nil,
    position: ChannelPipeline.Position = .last,
    completion: (@Sendable (HTTPVersion, HTTPRequest) -> EventLoopFuture<Void>)? = nil
  ) -> EventLoopFuture<Void> {
    let position = NIOLoopBound(position, eventLoop: eventLoop)
    if eventLoop.inEventLoop {
      return eventLoop.makeCompletedFuture {
        try self.pipeline.syncOperations.configureHTTPTunnelPipeline(
          mode: mode,
          authenticationRequired: authenticationRequired,
          passwordReference: passwordReference,
          destinationAddress: destinationAddress,
          position: position.value,
          completion: completion
        )
      }
    } else {
      return eventLoop.submit {
        try self.pipeline.syncOperations.configureHTTPTunnelPipeline(
          mode: mode,
          authenticationRequired: authenticationRequired,
          passwordReference: passwordReference,
          destinationAddress: destinationAddress,
          position: position.value,
          completion: completion
        )
      }
    }
  }
}

extension ChannelPipeline.SynchronousOperations {

  /// Configure a HTTP tunnel.
  ///
  /// - Parameters:
  ///   - mode: The mode this pipeline will operate in, server or client.
  ///   - authenticationRequired: The flag whether the tunnel require authentication.
  ///   - passwordReference: The password reference for authentication.
  ///   - destinationAddress: The target address this tunnel work for. Client only.
  ///   - position: The position in the pipeline whitch to insert the handlers.
  ///   - completion: The completion handler when negotation complete. Server only.
  public func configureHTTPTunnelPipeline(
    mode: NEHTTPMode,
    authenticationRequired: Bool = false,
    passwordReference: String,
    destinationAddress: NWEndpoint? = nil,
    position: ChannelPipeline.Position = .last,
    completion: (@Sendable (HTTPVersion, HTTPRequest) -> EventLoopFuture<Void>)? = nil
  ) throws {
    eventLoop.assertInEventLoop()

    switch mode {
    case .client:
      guard let destinationAddress else {
        fatalError("Missing required destination address.")
      }
      let handlers: [ChannelHandler] = [
        HTTPProxyClientHandler(
          passwordReference: passwordReference,
          authenticationRequired: authenticationRequired,
          destinationAddress: destinationAddress
        ),
        HTTPRequestEncoder(),
        ByteToMessageHandler(HTTPResponseDecoder()),
      ]
      try self.addHandlers(handlers, position: position)
    case .server:
      guard let completion else {
        fatalError("Missing required completion handler.")
      }
      let responseEncoder = HTTPResponseEncoder()
      let requestDecoder = ByteToMessageHandler(HTTPRequestDecoder())

      let handlers: [RemovableChannelHandler] = [
        responseEncoder,
        requestDecoder,
        HTTPProxyServerHandler(
          passwordReference: passwordReference,
          authenticationRequired: authenticationRequired,
          additionalHTTPHandlers: [responseEncoder, requestDecoder],
          completion: completion
        ),
      ]
      try self.addHandlers(handlers, position: position)
    }
  }
}
