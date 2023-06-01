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
@_exported import NEPrettyBytes
import NESHAKE128
@_exported import NIOCore

/// A decoder that split the received `ByteBuffer` by the number of bytes specified in a fixed length header
/// contained within the buffer.
final public class LengthFieldBasedFrameDecoder: ByteToMessageDecoder {

  public typealias InboundOut = ByteBuffer

  private let symmetricKey: [UInt8]
  private let nonce: [UInt8]
  private let configuration: Configuration
  private var frameOffset: UInt16 = 0

  /// The frame length and padding record.
  private var size: (UInt16, Int)?

  private lazy var shake128: SHAKE128 = {
    var shake128 = SHAKE128()
    shake128.update(data: nonce)
    return shake128
  }()

  public init(symmetricKey: [UInt8], nonce: [UInt8], configuration: Configuration) {
    self.symmetricKey = Array(SHA256.hash(data: symmetricKey).prefix(16))
    self.nonce = Array(SHA256.hash(data: nonce).prefix(16))
    self.configuration = configuration
  }

  public func decode(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws
    -> DecodingState
  {
    switch configuration.algorithm {
    case .aes128Gcm, .chaCha20Poly1305:
      guard let size = try parseLengthField(context: context, buffer: &buffer) else {
        return .needMoreData
      }
      self.size = size

      guard let frame = try parseFrame(context: context, buffer: &buffer) else {
        return .needMoreData
      }

      context.fireChannelRead(wrapInboundOut(frame))

      return .continue
    case .aes128cfb, .none, .zero:
      throw CodingError.operationUnsupported
    }
  }

  /// Parse length field with specified context and buffer.
  /// - Parameters:
  ///   - context: The `ChannelHandlerContext` which this decoder belongs to.
  ///   - buffer: The buffer from which we decode.
  /// - Returns: `(frameLength, padding)` if length field decode success or `nil` if need more data.
  private func parseLengthField(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws
    -> (UInt16, Int)?
  {
    guard size == nil else {
      return size
    }

    let overhead = configuration.algorithm.overhead

    let frameLength = configuration.options.contains(.authenticatedLength) ? 2 + overhead : 2

    guard buffer.readableBytes >= frameLength else {
      return nil
    }

    let frameLengthData = buffer.readBytes(length: frameLength) ?? []

    var padding = 0
    if configuration.options.shouldPadding {
      shake128.read(digestSize: 2).withUnsafeBytes {
        padding = Int($0.load(as: UInt16.self).bigEndian % 64)
      }
    }

    guard configuration.options.contains(.authenticatedLength) else {
      guard configuration.options.contains(.masking) else {
        return frameLengthData.withUnsafeBytes {
          ($0.load(as: UInt16.self), padding)
        }
      }

      return shake128.read(digestSize: 2).withUnsafeBytes {
        let mask = $0.load(as: UInt16.self).bigEndian

        return frameLengthData.withUnsafeBytes {
          (mask ^ $0.load(as: UInt16.self).bigEndian, padding)
        }
      }
    }

    var symmetricKey = KDF16.deriveKey(
      inputKeyMaterial: .init(data: symmetricKey),
      info: [Data("auth_len".utf8)]
    )

    let nonce = withUnsafeBytes(of: frameOffset.bigEndian) {
      Array($0) + Array(self.nonce.prefix(12).suffix(10))
    }

    if configuration.algorithm == .aes128Gcm {
      let sealedBox = try AES.GCM.SealedBox.init(combined: nonce + frameLengthData)
      return try AES.GCM.open(sealedBox, using: symmetricKey).withUnsafeBytes {
        ($0.load(as: UInt16.self).bigEndian + UInt16(overhead), padding)
      }
    } else {
      symmetricKey = symmetricKey.withUnsafeBytes {
        generateChaChaPolySymmetricKey(inputKeyMaterial: $0)
      }
      let sealedBox = try ChaChaPoly.SealedBox.init(combined: nonce + frameLengthData)
      return try ChaChaPoly.open(sealedBox, using: symmetricKey).withUnsafeBytes {
        ($0.load(as: UInt16.self).bigEndian + UInt16(overhead), padding)
      }
    }
  }

  /// Parse frame with specified context and buffer.
  /// - Parameters:
  ///   - context: The `ChannelHandlerContext` which this decoder belongs to.
  ///   - buffer: The buffer from which we decode.
  /// - returns: `ByteBuffer` if frame decode success or `nil` if need more data.
  private func parseFrame(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws
    -> ByteBuffer?
  {
    // TCP
    guard let size: (frameLength: UInt16, padding: Int) = self.size else {
      return nil
    }

    guard buffer.readableBytes >= Int(size.frameLength) else {
      return nil
    }

    // Receive VMESS EOF.
    guard size.frameLength != configuration.algorithm.overhead + size.padding else {
      return parseLastFrame(context: context, buffer: &buffer)
    }

    let nonce = withUnsafeBytes(of: frameOffset.bigEndian) {
      Array($0) + Array(self.nonce.prefix(12).suffix(10))
    }

    // Remove random padding bytes.
    let combined =
      nonce + (buffer.readBytes(length: Int(size.frameLength))?.dropLast(size.padding) ?? [])

    var frame: Data
    if configuration.algorithm == .aes128Gcm {
      frame = try AES.GCM.open(.init(combined: combined), using: .init(data: symmetricKey))
    } else {
      let symmetricKey = generateChaChaPolySymmetricKey(inputKeyMaterial: symmetricKey)
      frame = try ChaChaPoly.open(.init(combined: combined), using: symmetricKey)
    }

    frameOffset &+= 1

    self.size = nil

    let frameBuffer = context.channel.allocator.buffer(bytes: frame)

    return frameBuffer
  }

  /// Recieve EOF and we should reset all state to it's initial value.
  ///
  /// For current version of VMESS protocol this always return empty frame buffer.
  /// - Parameters:
  ///   - context: The `ChannelHandlerContext` which this decoder belongs to.
  ///   - buffer: The buffer from which we decode.
  /// - Returns: The parsed frame buffer.
  private func parseLastFrame(context: ChannelHandlerContext, buffer: inout ByteBuffer)
    -> ByteBuffer
  {
    // We don't care about contents of this frame just remove it from buffer.
    _ = buffer.readBytes(length: Int(size?.0 ?? 0))

    frameOffset = 0
    size = nil

    if configuration.options.contains(.masking) {
      shake128 = .init()
      shake128.update(data: nonce)
    }

    return context.channel.allocator.buffer(capacity: 0)
  }
}

@available(*, unavailable)
extension LengthFieldBasedFrameDecoder: Sendable {}
