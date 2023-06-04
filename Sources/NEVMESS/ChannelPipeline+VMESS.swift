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
  ///   - authenticationCode: VMESS head authentication code. Defaults to `UInt8.random(in: 0 ... .max)`.
  ///   - contentSecurity: VMESS data stream security settings..
  ///   - symmetricKey: Symmetric key for encryption/decryption.
  ///   - nonce: Nonce for encryption/decryption.
  ///   - user: VMESS client ID.
  ///   - commandCode: Command code for VMESS request/response. Defaults to `.tcp`.
  ///   - options: VMESS stream options. Defaults to `.masking`.
  ///   - destinationAddress: The destination for proxy connection.
  public func addVMESSClientHandlers(
    position: Position = .last,
    authenticationCode: UInt8 = .random(in: 0 ... .max),
    contentSecurity: ContentSecurity,
    symmetricKey: SymmetricKey,
    nonce: Nonce,
    user: UUID,
    commandCode: CommandCode = .tcp,
    options: StreamOptions = .masking,
    destinationAddress: NetAddress
  ) -> EventLoopFuture<Void> {
    let eventLoopFuture: EventLoopFuture<Void>

    if eventLoop.inEventLoop {
      let result = Result<Void, Error> {
        try syncOperations.addVMESSClientHandlers(
          position: position,
          authenticationCode: authenticationCode,
          contentSecurity: contentSecurity,
          symmetricKey: symmetricKey,
          nonce: nonce,
          user: user,
          commandCode: commandCode,
          options: options,
          destinationAddress: destinationAddress
        )
      }
      eventLoopFuture = eventLoop.makeCompletedFuture(result)
    } else {
      eventLoopFuture = eventLoop.submit {
        try self.syncOperations.addVMESSClientHandlers(
          position: position,
          authenticationCode: authenticationCode,
          contentSecurity: contentSecurity,
          symmetricKey: symmetricKey,
          nonce: nonce,
          user: user,
          commandCode: commandCode,
          options: options,
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
  ///   - authenticationCode: VMESS head authentication code. Defaults to `UInt8.random(in: 0 ... .max)`.
  ///   - contentSecurity: VMESS data stream security settings..
  ///   - symmetricKey: Symmetric key for encryption/decryption.
  ///   - nonce: Nonce for encryption/decryption.
  ///   - user: VMESS client ID.
  ///   - commandCode: Command code for VMESS request/response. Defaults to `.tcp`.
  ///   - options: VMESS stream options. Defaults to `.masking`.
  ///   - destinationAddress: The destination for proxy connection.
  public func addVMESSClientHandlers(
    position: ChannelPipeline.Position = .last,
    authenticationCode: UInt8 = .random(in: 0 ... .max),
    contentSecurity: ContentSecurity,
    symmetricKey: SymmetricKey,
    nonce: Nonce,
    user: UUID,
    commandCode: CommandCode = .tcp,
    options: StreamOptions = .masking,
    destinationAddress: NetAddress
  ) throws {
    eventLoop.assertInEventLoop()

    guard symmetricKey.bitCount == SymmetricKeySize.bits128.bitCount else {
      throw CryptoKitError.incorrectKeySize
    }

    let messageEncoder = VMESSEncoder<VMESSPart<VMESSRequestHead, ByteBuffer>>(
      authenticationCode: authenticationCode,
      contentSecurity: contentSecurity,
      symmetricKey: symmetricKey,
      nonce: nonce,
      options: options
    )

    let messageDecoder = VMESSDecoder<VMESSPart<VMESSResponseHead, ByteBuffer>>(
      authenticationCode: authenticationCode,
      contentSecurity: contentSecurity,
      symmetricKey: symmetricKey,
      nonce: nonce,
      options: options
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
