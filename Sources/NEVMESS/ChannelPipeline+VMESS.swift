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

import Crypto
import Foundation
import NEMisc
import NEPrettyBytes
import NIOCore

extension ChannelPipeline {

  /// Configure a `ChannelPipeline` for use as a VMESS proxy client.
  /// - Parameters:
  ///   - position: The position in the `ChannelPipeline` where to add the HTTP proxy client handlers. Defaults to `.last`.
  ///   - contentSecurity: VMESS data stream security settings..
  ///   - user: VMESS client ID.
  ///   - commandCode: Command code for VMESS request/response. Defaults to `.tcp`.
  ///   - destinationAddress: The destination for proxy connection.
  public func addVMESSClientHandlers(
    position: Position = .last,
    contentSecurity: ContentSecurity,
    user: UUID,
    commandCode: CommandCode = .tcp,
    destinationAddress: NetAddress
  ) -> EventLoopFuture<Void> {
    let eventLoopFuture: EventLoopFuture<Void>

    if eventLoop.inEventLoop {
      let result = Result<Void, Error> {
        try syncOperations.addVMESSClientHandlers(
          position: position,
          contentSecurity: contentSecurity,
          user: user,
          commandCode: commandCode,
          destinationAddress: destinationAddress
        )
      }
      eventLoopFuture = eventLoop.makeCompletedFuture(result)
    } else {
      eventLoopFuture = eventLoop.submit {
        try self.syncOperations.addVMESSClientHandlers(
          position: position,
          contentSecurity: contentSecurity,
          user: user,
          commandCode: commandCode,
          destinationAddress: destinationAddress
        )
      }
    }
    return eventLoopFuture
  }
}

extension ChannelPipeline.SynchronousOperations {

  /// Configure a `ChannelPipeline` for use as a VMESS proxy client.
  /// - Parameters:
  ///   - position: The position in the `ChannelPipeline` where to add the HTTP proxy client handlers. Defaults to `.last`.
  ///   - contentSecurity: VMESS data stream security settings..
  ///   - user: VMESS client ID.
  ///   - commandCode: Command code for VMESS request/response. Defaults to `.tcp`.
  ///   - destinationAddress: The destination for proxy connection.
  public func addVMESSClientHandlers(
    position: ChannelPipeline.Position = .last,
    contentSecurity: ContentSecurity,
    user: UUID,
    commandCode: CommandCode = .tcp,
    destinationAddress: NetAddress
  ) throws {
    eventLoop.assertInEventLoop()

    let authenticationCode = UInt8.random(in: .min ... .max)
    let symmetricKey = SymmetricKey(size: .bits128)
    var nonce = Array(repeating: UInt8.zero, count: 16)
    nonce.withUnsafeMutableBytes {
      $0.initializeWithRandomBytes(count: 16)
    }
    let options = StreamOptions.chunkStream

    let messageEncoder = VMESSEncoder<VMESSPart<VMESSRequestHead, ByteBuffer>>(
      authenticationCode: authenticationCode,
      contentSecurity: contentSecurity,
      symmetricKey: symmetricKey,
      nonce: nonce,
      options: options,
      commandCode: commandCode
    )

    let messageDecoder = VMESSDecoder<VMESSPart<VMESSResponseHead, ByteBuffer>>(
      contentSecurity: contentSecurity,
      symmetricKey: symmetricKey,
      nonce: Array(nonce),
      options: options,
      commandCode: commandCode
    )

    let handlers: [ChannelHandler] = [
      ByteToMessageHandler(messageDecoder),
      messageEncoder,
      VMESSClientHandler(
        user: user,
        authenticationCode: authenticationCode,
        contentSecurity: contentSecurity,
        options: options,
        commandCode: commandCode,
        destinationAddress: destinationAddress
      ),
    ]

    try addHandlers(handlers, position: position)
  }
}
