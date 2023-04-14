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
@_exported import NEMisc
@_exported import NEPrettyBytes
import NESHAKE128
@_exported import NIOCore

final public class RequestEncodingHandler: ChannelOutboundHandler {

  public typealias OutboundIn = ByteBuffer

  public typealias OutboundOut = ByteBuffer

  private let authenticationCode: UInt8

  private let symmetricKey: SecureBytes

  private let nonce: SecureBytes

  /// Request encoder configuration object.
  private let configuration: Configuration

  private let forceAEADEncoding: Bool

  /// Request address.
  private let address: NetAddress

  private var encoder: LengthFieldBasedFrameEncoder

  private var buffer: ByteBuffer?

  private enum State {
    case idle
    case preparing
    case processing
    case complete
    case fail(Error)

    var isIdle: Bool {
      guard case .idle = self else {
        return false
      }
      return true
    }
  }

  private var state: State = .idle

  /// Initialize an instance of `RequestHeaderEncoder` with specified logger, authenticationCode, symmetricKey, nonce, configuration, forceAEADEncoding and address.
  /// - Parameters:
  ///   - logger: The logger object use to logging.
  ///   - authenticationCode: Request header authentication code.
  ///   - symmetricKey: SymmetricKey of the encrpytor.
  ///   - nonce: Nonce of the encryptor.
  ///   - configuration: The configuration object contains encoder configurations.
  ///   - forceAEADEncoding: A boolean value determinse whether encoder should use AEAD encoding.
  ///   - destinationAddress: The requet address.
  public init(
    authenticationCode: UInt8,
    symmetricKey: SecureBytes,
    nonce: SecureBytes,
    configuration: Configuration,
    forceAEADEncoding: Bool = true,
    taskAddress: NetAddress
  ) {
    self.authenticationCode = authenticationCode
    self.symmetricKey = symmetricKey
    self.nonce = nonce
    self.configuration = configuration
    self.forceAEADEncoding = forceAEADEncoding
    self.address = taskAddress
    self.encoder = .init(
      symmetricKey: symmetricKey,
      nonce: nonce,
      configuration: configuration
    )
  }

  public func handlerAdded(context: ChannelHandlerContext) {
    precondition(state.isIdle, "Illegal state when adding to channel: \(state)")
    state = .preparing
    buffer = context.channel.allocator.buffer(capacity: 256)
  }

  public func handlerRemoved(context: ChannelHandlerContext) {
    state = .complete
    buffer = nil
  }

  public func write(
    context: ChannelHandlerContext,
    data: NIOAny,
    promise: EventLoopPromise<Void>?
  ) {
    do {
      buffer?.clear()

      switch state {
      case .idle:
        preconditionFailure(
          "\(self) \(#function) called before it was added to a channel."
        )
      case .preparing:
        buffer?.writeBytes(try prepareHeadPart())
        state = .processing
        break
      case .processing:
        break
      case .complete:
        return
      case .fail:
        return
      }

      try encoder.encode(data: unwrapOutboundIn(data), out: &buffer!)
      context.write(wrapOutboundOut(buffer!), promise: promise)
    } catch {
      state = .fail(error)
      promise?.fail(error)
      context.fireErrorCaught(error)
    }
  }

  /// Prepare HEAD part data for request.
  ///
  /// If use AEAD to encrypt request then the HEAD part only contains instruction else HEAD part contains
  /// authentication info and instruction two parts.
  /// - Returns: Encrypted HEAD part data.
  private func prepareHeadPart() throws -> Data {
    let date = Date() + TimeInterval.random(in: -30...30)
    let timestamp = UInt64(date.timeIntervalSince1970)

    var result = Data()
    result += try prepareAuthenticationInfoPart(timestamp: timestamp)
    result += try prepareInstructionPart(timestamp: timestamp)
    return result
  }

  /// Prepare HEAD authentication info part data with specified timestamp.
  ///
  /// If use AEAD to encrypt request just return empty data instead.
  /// - Parameter timestamp: UTC UInt64 timestamp.
  /// - Returns: Encrypted authentication info part data.
  private func prepareAuthenticationInfoPart(timestamp: UInt64) throws -> Data {
    guard !forceAEADEncoding else {
      return .init()
    }

    return withUnsafeBytes(of: configuration.id) {
      var hasher = HMAC<Insecure.MD5>(key: .init(data: $0))
      return withUnsafeBytes(of: timestamp.bigEndian) {
        hasher.update(data: $0)
        return Data(hasher.finalize())
      }
    }
  }

  /// Prepare HEAD instruction part data with specified timestamp.
  /// - Parameter timestamp: UTC UInt64 timestamp.
  /// - Returns: Encrypted instruction part data.
  private func prepareInstructionPart(timestamp: UInt64) throws -> Data {
    var buffer = ByteBuffer()
    buffer.writeInteger(ProtocolVersion.v1.rawValue)
    buffer.writeBytes(nonce)
    buffer.writeBytes(symmetricKey)
    buffer.writeInteger(authenticationCode)
    buffer.writeInteger(configuration.options.rawValue)

    let padding = UInt8.random(in: 0...16)
    buffer.writeInteger((padding << 4) | configuration.algorithm.rawValue)
    // Write zero as keeper.
    buffer.writeInteger(UInt8(0))
    buffer.writeInteger(configuration.command.rawValue)

    if configuration.command != .mux {
      buffer.writeAddress(address)
    }

    if padding > 0 {
      buffer.writeBytes(SecureBytes(count: Int(padding)))
    }

    buffer.writeInteger(
      buffer.withUnsafeReadableBytes {
        commonFNV1a($0)
      }
    )

    let inputKeyMaterial = generateCmdKey(configuration.id)
    if forceAEADEncoding {
      let authenticatedData = try generateAuthenticatedData(inputKeyMaterial)
      let randomPath = Array(SecureBytes(count: 8))

      var info = [
        [],
        authenticatedData,
        randomPath,
      ]

      let sealedLengthBox: AES.GCM.SealedBox = try withUnsafeBytes(
        of: UInt16(buffer.readableBytes).bigEndian
      ) {
        info[0] = Array(kDFSaltConstVMessHeaderPayloadLengthAEADKey)
        let symmetricKey = KDF16.deriveKey(inputKeyMaterial: inputKeyMaterial, info: info)

        info[0] = Array(kDFSaltConstVMessHeaderPayloadLengthAEADIV)
        let nonce = try KDF12.deriveKey(inputKeyMaterial: inputKeyMaterial, info: info)
          .withUnsafeBytes { ptr in
            try AES.GCM.Nonce.init(data: ptr)
          }
        return try AES.GCM.seal(
          $0,
          using: symmetricKey,
          nonce: nonce,
          authenticating: authenticatedData
        )
      }

      let sealedPayloadBox: AES.GCM.SealedBox = try buffer.withUnsafeReadableBytes {
        info[0] = Array(kDFSaltConstVMessHeaderPayloadAEADKey)
        let symmetricKey = KDF16.deriveKey(inputKeyMaterial: inputKeyMaterial, info: info)

        info[0] = Array(kDFSaltConstVMessHeaderPayloadAEADIV)
        let nonce = try KDF12.deriveKey(inputKeyMaterial: inputKeyMaterial, info: info)
          .withUnsafeBytes { ptr in
            try AES.GCM.Nonce.init(data: ptr)
          }
        return try AES.GCM.seal(
          $0,
          using: symmetricKey,
          nonce: nonce,
          authenticating: authenticatedData
        )
      }

      return authenticatedData
        + sealedLengthBox.ciphertext
        + sealedLengthBox.tag
        + randomPath
        + sealedPayloadBox.ciphertext
        + sealedPayloadBox.tag
    } else {
      // Hash timestamp original impl of go see `client.go hashTimestamp` in v2flay.
      var hasher = Insecure.MD5.init()
      withUnsafeBytes(of: timestamp.bigEndian) {
        for _ in 0..<4 {
          hasher.update(bufferPointer: $0)
        }
      }

      var result = Data(repeating: 0, count: buffer.readableBytes)
      try buffer.withUnsafeReadableBytes { inPtr in
        try result.withUnsafeMutableBytes { dataOut in
          try commonAESCFB128Encrypt(
            nonce: Array(hasher.finalize()),
            key: inputKeyMaterial,
            dataIn: inPtr,
            dataOut: dataOut,
            dataOutAvailable: buffer.readableBytes
          )
        }
      }

      return result
    }
  }

  /// Generate authenticated data with specified key.
  /// - Parameter key: Input key material.
  /// - Returns: Encrypted authenticated data bytes.
  private func generateAuthenticatedData(_ key: SymmetricKey) throws -> [UInt8] {
    var byteBuffer = withUnsafeBytes(
      of: UInt64(Date().timeIntervalSince1970).bigEndian,
      Array.init
    )
    byteBuffer += Array(SecureBytes(count: 4))
    byteBuffer += withUnsafeBytes(of: CRC32.checksum(byteBuffer).bigEndian, Array.init)

    let inputKeyMaterial = KDF16.deriveKey(
      inputKeyMaterial: key,
      info: [Array(kDFSaltConstAuthIDEncryptionKey)]
    )

    var result = [UInt8](repeating: 0, count: byteBuffer.count + 16)

    try byteBuffer.withUnsafeBytes { inPtr in
      try result.withUnsafeMutableBytes { outPtr in
        try commonAESEncrypt(
          key: inputKeyMaterial,
          dataIn: inPtr,
          dataOut: outPtr,
          dataOutAvailable: byteBuffer.count + 16
        )
      }
    }

    return Array(result.prefix(16))
  }
}

@available(*, unavailable)
extension RequestEncodingHandler: Sendable {}
