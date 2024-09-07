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
import NEAddressProcessing
import NEPrettyBytes
import NIOCore

extension Channel {

  /// Configure a VMESS proxy channel for client.
  ///
  /// - Parameters:
  ///   - contentSecurity: VMESS data stream security settings..
  ///   - user: VMESS client ID.
  ///   - commandCode: Command code for VMESS request/response. Defaults to `.tcp`.
  ///   - destinationAddress: The destination for proxy connection, Client only.
  ///   - position: The position in the pipeline whitch to insert the handlers.
  /// - Returns: An `EventLoopFuture<Void>` that completes when the channel is ready.
  @preconcurrency public func configureVMESSPipeline(
    contentSecurity: ContentSecurity,
    user: UUID,
    commandCode: CommandCode = .tcp,
    destinationAddress: Address,
    position: ChannelPipeline.Position = .last
  ) -> EventLoopFuture<Void> {
    _configureVMESSPipeline(
      contentSecurity: contentSecurity,
      user: user,
      commandCode: commandCode,
      destinationAddress: destinationAddress,
      position: position
    )
  }

  private func _configureVMESSPipeline(
    contentSecurity: ContentSecurity,
    user: UUID,
    commandCode: CommandCode = .tcp,
    destinationAddress: Address,
    position: ChannelPipeline.Position = .last
  ) -> EventLoopFuture<Void> {
    if eventLoop.inEventLoop {
      return eventLoop.makeCompletedFuture {
        try self.pipeline.syncOperations.configureVMESSPipeline(
          contentSecurity: contentSecurity,
          user: user,
          commandCode: commandCode,
          destinationAddress: destinationAddress,
          position: position
        )
      }
    } else {
      return eventLoop.submit {
        try self.pipeline.syncOperations.configureVMESSPipeline(
          contentSecurity: contentSecurity,
          user: user,
          commandCode: commandCode,
          destinationAddress: destinationAddress,
          position: position
        )
      }
    }
  }
}

extension ChannelPipeline.SynchronousOperations {

  /// Configure a VMESS proxy channel pipeline for client.
  ///
  /// - Parameters:
  ///   - contentSecurity: VMESS data stream security settings..
  ///   - user: VMESS client ID.
  ///   - commandCode: Command code for VMESS request/response. Defaults to `.tcp`.
  ///   - destinationAddress: The destination for proxy connection, Client only.
  ///   - position: The position in the pipeline whitch to insert the handlers.
  /// - Throws: If the pipeline could not be configured.
  public func configureVMESSPipeline(
    contentSecurity: ContentSecurity,
    user: UUID,
    commandCode: CommandCode = .tcp,
    destinationAddress: Address,
    position: ChannelPipeline.Position = .last
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
