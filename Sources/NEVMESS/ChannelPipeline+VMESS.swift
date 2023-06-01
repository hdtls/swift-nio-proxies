//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2022 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation
@_exported import NEMisc
import NEPrettyBytes
@_exported import NIOCore

extension ChannelPipeline {

  public func addVMESSClientHandlers(
    position: Position = .last,
    username: UUID,
    destinationAddress: NetAddress
  ) -> EventLoopFuture<Void> {
    let eventLoopFuture: EventLoopFuture<Void>

    if eventLoop.inEventLoop {
      let result = Result<Void, Error> {
        try syncOperations.addVMESSClientHandlers(
          position: position,
          username: username,
          destinationAddress: destinationAddress
        )
      }
      eventLoopFuture = eventLoop.makeCompletedFuture(result)
    } else {
      eventLoopFuture = eventLoop.submit({
        try self.syncOperations.addVMESSClientHandlers(
          position: position,
          username: username,
          destinationAddress: destinationAddress
        )
      })
    }

    return eventLoopFuture
  }
}

extension ChannelPipeline.SynchronousOperations {

  public func addVMESSClientHandlers(
    position: ChannelPipeline.Position = .last,
    username: UUID,
    destinationAddress: NetAddress
  ) throws {
    eventLoop.assertInEventLoop()

    let configuration: Configuration = .init(
      id: username,
      algorithm: .aes128Gcm,
      command: .tcp,
      options: .masking
    )

    var symmetricKey = Array(repeating: UInt8.zero, count: 16)
    symmetricKey.withUnsafeMutableBytes {
      $0.initializeWithRandomBytes(count: 16)
    }
    var nonce = Array(repeating: UInt8.zero, count: 16)
    nonce.withUnsafeMutableBytes {
      $0.initializeWithRandomBytes(count: 16)
    }
    let authenticationCode = UInt8.random(in: 0...UInt8.max)

    let outboundHandler = RequestEncodingHandler(
      authenticationCode: authenticationCode,
      symmetricKey: symmetricKey,
      nonce: nonce,
      configuration: configuration,
      taskAddress: destinationAddress
    )

    let responseDecoder = ResponseHeaderDecoder(
      authenticationCode: authenticationCode,
      symmetricKey: symmetricKey,
      nonce: nonce,
      configuration: configuration
    )

    let frameDecoder = LengthFieldBasedFrameDecoder(
      symmetricKey: symmetricKey,
      nonce: nonce,
      configuration: configuration
    )

    let handlers: [ChannelHandler] = [
      ByteToMessageHandler(responseDecoder),
      ByteToMessageHandler(frameDecoder),
      outboundHandler,
    ]

    try addHandlers(handlers, position: position)
  }
}
