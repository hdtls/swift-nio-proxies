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

  /// Configure a `ChannelPipeline` for use as a Shadowsocks client.
  /// - Parameters:
  ///   - position: The position in the `ChannelPipeline` where to add the Shadowsocks proxy client handlers. Defaults to `.last`.
  ///   - algorithm: The algorithm to use to encrypt/decript stream for this connection.
  ///   - passwordReference: The passwordReference to use to generate symmetric key for stream encription/decryption.
  ///   - destinationAddress: The destination for proxy connection.
  /// - Returns: An `EventLoopFuture` that will fire when the pipeline is configured.
  public func addSSClientHandlers(
    position: Position = .last,
    algorithm: Algorithm,
    passwordReference: String,
    destinationAddress: NetAddress
  ) -> EventLoopFuture<Void> {

    guard eventLoop.inEventLoop else {
      return eventLoop.submit {
        try self.syncOperations.addSSClientHandlers(
          position: position,
          algorithm: algorithm,
          passwordReference: passwordReference,
          destinationAddress: destinationAddress
        )
      }
    }

    return eventLoop.makeCompletedFuture {
      try syncOperations.addSSClientHandlers(
        position: position,
        algorithm: algorithm,
        passwordReference: passwordReference,
        destinationAddress: destinationAddress
      )
    }
  }
}

extension ChannelPipeline.SynchronousOperations {

  /// Configure a `ChannelPipeline` for use as a Shadowsocks client.
  /// - Parameters:
  ///   - position: The position in the `ChannelPipeline` where to add the Shadowsocks proxy client handlers. Defaults to `.last`.
  ///   - algorithm: The algorithm to use to encrypt/decript stream for this connection.
  ///   - passwordReference: The passwordReference to use to generate symmetric key for stream encription/decryption.
  ///   - destinationAddress: The destination for proxy connection.
  /// - Throws: If the pipeline could not be configured.
  public func addSSClientHandlers(
    position: ChannelPipeline.Position = .last,
    algorithm: Algorithm,
    passwordReference: String,
    destinationAddress: NetAddress
  ) throws {
    eventLoop.assertInEventLoop()
    let inboundDecoder = ResponseDecoder(
      algorithm: algorithm,
      passwordReference: passwordReference
    )
    let outboundHandler = RequestEncoder(
      algorithm: algorithm,
      passwordReference: passwordReference,
      destinationAddress: destinationAddress
    )
    let handlers: [ChannelHandler] = [ByteToMessageHandler(inboundDecoder), outboundHandler]
    try addHandlers(handlers, position: position)
  }
}
