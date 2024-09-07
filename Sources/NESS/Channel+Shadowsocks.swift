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

import NEAddressProcessing
import NIOCore

extension Channel {

  /// Configure a Shadowsocks proxy channel for client.
  ///
  /// - Parameters:
  ///   - algorithm: The algorithm to use to encrypt/decript stream for this connection.
  ///   - passwordReference: The passwordReference to use to generate symmetric key for stream encription/decryption.
  ///   - destinationAddress: The destination for proxy connection.
  ///   - position: The position in the pipeline whitch to insert the handlers.
  /// - Returns: An `EventLoopFuture<Void>` that completes when the channel is ready.
  public func configureSSPipeline(
    algorithm: Algorithm,
    passwordReference: String,
    destinationAddress: Address,
    position: ChannelPipeline.Position = .last
  ) -> EventLoopFuture<Void> {
    if eventLoop.inEventLoop {
      return eventLoop.makeCompletedFuture {
        try self.pipeline.syncOperations.configureSSPipeline(
          algorithm: algorithm,
          passwordReference: passwordReference,
          destinationAddress: destinationAddress,
          position: position
        )
      }
    } else {
      return eventLoop.submit {
        try self.pipeline.syncOperations.configureSSPipeline(
          algorithm: algorithm,
          passwordReference: passwordReference,
          destinationAddress: destinationAddress,
          position: position
        )
      }
    }
  }
}

extension ChannelPipeline.SynchronousOperations {

  /// Configure a Shadowsocks proxy channel pipeline for client.
  ///
  /// - Parameters:
  ///   - algorithm: The algorithm to use to encrypt/decript stream for this connection.
  ///   - passwordReference: The passwordReference to use to generate symmetric key for stream encription/decryption.
  ///   - destinationAddress: The destination for proxy connection.
  ///   - position: The position in the pipeline whitch to insert the handlers.
  /// - Throws: If the pipeline could not be configured.
  public func configureSSPipeline(
    algorithm: Algorithm,
    passwordReference: String,
    destinationAddress: Address,
    position: ChannelPipeline.Position = .last
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
