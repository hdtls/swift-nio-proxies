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

import Crypto
import Foundation
@_exported import NIOCore

///
/// Spec: http://shadowsocks.org/en/wiki/AEAD-Ciphers.html
///
/// TCP
///
/// An AEAD encrypted TCP stream starts with a randomly generated salt to derive the per-session subkey, followed by any
/// number of encrypted chunks. Each chunk has the following structure:
///
///      [encrypted payload length][length tag][encrypted payload][payload tag]
///
/// Payload length is a 2-byte big-endian unsigned integer capped at 0x3FFF. The higher two bits are reserved and must be
/// set to zero. Payload is therefore limited to 16*1024 - 1 bytes.
///
/// The first AEAD encrypt/decrypt operation uses a counting nonce starting from 0. After each encrypt/decrypt operation,
/// the nonce is incremented by one as if it were an unsigned little-endian integer. Note that each TCP chunk involves
/// two AEAD encrypt/decrypt operation: one for the payload length, and one for the payload. Therefore each chunk
/// increases the nonce twice.
///
/// UDP
///
/// An AEAD encrypted UDP packet has the following structure:
///
///      [salt][encrypted payload][tag]
///
/// The salt is used to derive the per-session subkey and must be generated randomly to ensure uniqueness. Each UDP
/// packet is encrypted/decrypted i`ndependently, using the derived subkey and a nonce with all zero bytes.
///
///

final public class ResponseDecoder: ByteToMessageDecoder {

  public typealias InboundOut = ByteBuffer

  private let algorithm: Algorithm

  private let passwordReference: String

  private var symmetricKey: SymmetricKey!

  private var nonce: [UInt8]

  /// Initialize an instance of `ResponseDecoder` with specified `algorithm` and `passwordReference`.
  /// - Parameters:
  ///   - algorithm: The algorithm use to decrypt response message.
  ///   - passwordReference: The password use to generate symmetric key for message decryptor.
  public init(algorithm: Algorithm, passwordReference: String) {
    self.algorithm = algorithm
    self.passwordReference = passwordReference
    self.nonce = .init(repeating: 0, count: 12)
  }

  public func decode(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws
    -> DecodingState
  {
    // Record data for fallback if buffer is not enough to decode as message.
    let fallbackNonce = nonce
    let fallbackBuffer = buffer

    // Decode salt from first packet.
    if symmetricKey == nil {
      let saltByteCount = algorithm == .aes128Gcm ? 16 : 32
      let keyByteCount = algorithm == .aes128Gcm ? 16 : 32
      guard buffer.readableBytes >= saltByteCount else {
        return .needMoreData
      }
      let salt = buffer.readBytes(length: saltByteCount)!
      symmetricKey = hkdfDerivedSymmetricKey(
        secretKey: passwordReference,
        salt: salt,
        outputByteCount: keyByteCount
      )
    }

    let tagByteCount = 16
    let trunkSize = 2
    var readLength = trunkSize + tagByteCount
    // Check if data is enough to decode as size message.
    guard buffer.readableBytes > readLength else {
      return .needMoreData
    }
    var byteBuffer = try process(message: buffer.readBytes(length: readLength)!, on: context)
    let size = byteBuffer.readInteger(as: UInt16.self)

    // Check if buffer is enougth to decode as response message.
    guard let size = size, buffer.readableBytes >= Int(size) + tagByteCount else {
      buffer = fallbackBuffer
      nonce = fallbackNonce
      return .needMoreData
    }
    readLength = Int(size) + tagByteCount
    byteBuffer = try process(message: buffer.readBytes(length: readLength)!, on: context)
    context.fireChannelRead(wrapInboundOut(byteBuffer))
    return .continue
  }

  private func process(message: [UInt8], on context: ChannelHandlerContext) throws -> ByteBuffer {
    var data: Data = .init()
    let combined = nonce + message

    switch algorithm {
    case .aes128Gcm, .aes256Gcm:
      data = try AES.GCM.open(.init(combined: combined), using: symmetricKey)
    case .chaCha20Poly1305:
      data = try ChaChaPoly.open(.init(combined: combined), using: symmetricKey)
    }
    nonce.increment(nonce.count)
    return context.channel.allocator.buffer(bytes: data)
  }
}

#if swift(>=5.7)
@available(*, unavailable)
extension ResponseDecoder: Sendable {}
#endif
