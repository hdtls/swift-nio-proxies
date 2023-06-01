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
@_exported import NEMisc
import NEPrettyBytes
@_exported import NIOCore

/// Connects to a Shadowsocks server to establish a proxied connection to a host.
final public class RequestEncoder: ChannelOutboundHandler {

  public typealias OutboundIn = ByteBuffer

  public typealias OutboundOut = ByteBuffer

  private let algorithm: Algorithm

  private let passwordReference: String

  private let destinationAddress: NetAddress

  private var symmetricKey: SymmetricKey?

  private var nonce: [UInt8]?

  /// Initialize an instance of `RequestEncoder` with specified `algorithm`, `passwordReference` and `destinationAddress`.
  /// - Parameters:
  ///   - algorithm: The algorithm to use to encrypt stream for this connection.
  ///   - passwordReference: The password to use to generate symmetric key for encryptor.
  ///   - destinationAddress: The desired end point - note that only IPv4, IPv6, and FQDNs are supported.
  public init(algorithm: Algorithm, passwordReference: String, destinationAddress: NetAddress) {
    self.algorithm = algorithm
    self.passwordReference = passwordReference
    self.destinationAddress = destinationAddress
  }

  public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?)
  {
    do {
      if symmetricKey == nil {
        let byteCount = algorithm == .aes128Gcm ? 16 : 32
        var saltBytes = Array(repeating: UInt8.zero, count: byteCount)
        saltBytes.withUnsafeMutableBytes {
          $0.initializeWithRandomBytes(count: byteCount)
        }
        nonce = .init(repeating: 0, count: 12)
        symmetricKey = hkdfDerivedSymmetricKey(
          secretKey: passwordReference,
          salt: saltBytes,
          outputByteCount: byteCount
        )

        // An AEAD encrypted TCP stream starts with a randomly generated salt to derive the per-session subkey.
        context.write(
          wrapOutboundOut(context.channel.allocator.buffer(bytes: saltBytes)),
          promise: promise
        )

        // Prepare address data.
        var byteBuffer = context.channel.allocator.buffer(capacity: 36)
        byteBuffer.writeAddress(destinationAddress)
        let message = byteBuffer.readBytes(length: byteBuffer.readableBytes) ?? []

        // Prepare address size data
        byteBuffer.writeInteger(UInt16(message.count))
        let sizeBytes = byteBuffer.readBytes(length: byteBuffer.readableBytes) ?? []

        byteBuffer.discardReadBytes()

        byteBuffer.writeBytes(try process(message: sizeBytes))
        byteBuffer.writeBytes(try process(message: message))

        context.write(wrapOutboundOut(byteBuffer), promise: promise)
      }

      var unwrapped = unwrapOutboundIn(data)

      // Encrypt and write trucks to server.
      while unwrapped.readableBytes > 0 {
        let maxLength = unwrapped.readableBytes & 0x3FFF
        if let message = unwrapped.readBytes(length: maxLength) {
          var byteBuffer = context.channel.allocator.buffer(
            capacity: MemoryLayout<UInt16>.size
          )
          byteBuffer.writeInteger(UInt16(message.count))
          let sizeBytes = byteBuffer.readBytes(length: byteBuffer.readableBytes) ?? []

          byteBuffer.discardReadBytes()

          byteBuffer.writeBytes(try process(message: sizeBytes))
          byteBuffer.writeBytes(try process(message: message))

          context.write(wrapOutboundOut(byteBuffer), promise: promise)
        }
      }
    } catch {
      context.fireErrorCaught(error)
    }
  }

  /// Process message into structure [ciphertext][tag].
  /// - Parameter message: the plaintext waiting to encrypt which confirm to `DataProtocol`
  private func process<Plaintext>(message: Plaintext) throws -> Data where Plaintext: DataProtocol {
    var bytes: Data = .init()
    guard let symmetricKey, let nonce else {
      return bytes
    }

    switch algorithm {
    case .aes128Gcm, .aes256Gcm:
      let sealedBox = try AES.GCM.seal(
        message,
        using: symmetricKey,
        nonce: .init(data: nonce)
      )
      bytes.append(sealedBox.ciphertext)
      bytes.append(sealedBox.tag)
    case .chaCha20Poly1305:
      let sealedBox = try ChaChaPoly.seal(
        message,
        using: symmetricKey,
        nonce: .init(data: nonce)
      )
      bytes.append(sealedBox.ciphertext)
      bytes.append(sealedBox.tag)
    }

    self.nonce?.increment(nonce.count)
    return bytes
  }
}

@available(*, unavailable)
extension RequestEncoder: Sendable {}
