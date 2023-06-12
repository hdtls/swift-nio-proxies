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
import NESHAKE128
import NIOCore

private enum VMESSEncodeKind: Sendable {
  case request
  case response
}

private class BetterVMESSWriter<In> where In: Equatable {

  enum HeadEncodingStrategy: Sendable {
    case useAEAD
    case useLegacy
  }

  private let kind: VMESSEncodeKind
  private let authenticationCode: UInt8
  private let contentSecurity: ContentSecurity
  private let symmetricKey: SymmetricKey
  private let nonce: Nonce
  private let options: StreamOptions
  private let commandCode: CommandCode
  private lazy var hasher: SHAKE128 = {
    var shake128 = SHAKE128()
    nonce.withUnsafeBytes { buffPtr in
      shake128.update(data: buffPtr)
    }
    return shake128
  }()
  private var nonceLeading = UInt16.zero
  private let headEncodingStrategy: HeadEncodingStrategy

  init(
    authenticationCode: UInt8,
    contentSecurity: ContentSecurity,
    symmetricKey: SymmetricKey,
    nonce: Nonce,
    options: StreamOptions,
    commandCode: CommandCode,
    headEncodingStrategy: HeadEncodingStrategy = .useAEAD
  ) {
    if In.self == VMESSPart<VMESSRequestHead, ByteBuffer>.self {
      self.kind = .request
    } else {
      preconditionFailure("unknown VMESS message type \(In.self)")
    }
    self.authenticationCode = authenticationCode
    self.symmetricKey = symmetricKey
    self.nonce = nonce
    var options = options
    switch contentSecurity {
    case .aes128Gcm, .chaCha20Poly1305:
      options.insert(.chunkMasking)
      options.insert(.globalPadding)
      self.contentSecurity = contentSecurity
    case .none:
      options.insert(.chunkMasking)
      options.insert(.globalPadding)
      self.contentSecurity = contentSecurity
    case .aes128Cfb:
      if options.contains(.chunkMasking) {
        options.insert(.globalPadding)
      }
      self.contentSecurity = contentSecurity
    case .auto:
      options.insert(.globalPadding)
      self.contentSecurity = contentSecurity
    case .zero:
      self.contentSecurity = .none
      if options.contains(.chunkMasking) {
        options.insert(.globalPadding)
      }
      options.remove(.chunkStream)
      options.remove(.chunkMasking)
    default:
      preconditionFailure("unsupported VMESS message content security")
    }
    self.options = options
    self.commandCode = commandCode
    self.headEncodingStrategy = headEncodingStrategy
  }

  func write(_ part: In) throws -> Data {
    switch kind {
    case .request:
      let part = part as! VMESSPart<VMESSRequestHead, ByteBuffer>
      let bytes: Data
      switch part {
      case .head(let headT):
        bytes = try prepareInstruction(request: headT)
      case .body(let bodyT):
        bytes = try prepareFrame(data: bodyT)
      case .end:
        bytes = try prepareLastFrame()
      }
      return bytes
    case .response:
      throw CodingError.operationUnsupported
    }
  }

  /// Prepare frame data with specified data.
  /// - Parameter data: Original data.
  /// - Returns: Encrypted frame data.
  private func prepareFrame(data: ByteBuffer) throws -> Data {
    var mutableData = data

    let maxLength: Int
    var finalize = Data()

    switch contentSecurity {
    case .none:
      guard options.contains(.chunkStream) else {
        finalize = Data(Array(buffer: mutableData))
        return finalize
      }

      guard commandCode == .udp else {
        // Transfer type stream...
        maxLength = 8192
        while mutableData.readableBytes > 0 {
          let sliceLength = min(maxLength, mutableData.readableBytes)
          let slice = mutableData.readBytes(length: sliceLength)!
          let frameLengthData = try prepareFrameLengthData(frameLength: sliceLength, nonce: [])
          finalize += frameLengthData
          finalize += slice
        }
        return finalize
      }

      maxLength = 64 * 1024 * 1024
      guard mutableData.readableBytes <= maxLength else {
        throw CodingError.payloadTooLarge
      }
      let encryptedSize = mutableData.readableBytes

      let padding = nextPadding()

      guard 2 + encryptedSize + padding <= 2048 else {
        throw CodingError.payloadTooLarge
      }

      let frameLengthData = try prepareFrameLengthData(
        frameLength: encryptedSize + padding,
        nonce: []
      )
      finalize += frameLengthData
      finalize += Array(buffer: mutableData)
      if padding > 0 {
        var paddingData = Data(repeating: .zero, count: padding)
        paddingData.withUnsafeMutableBytes { buffPtr in
          buffPtr.initializeWithRandomBytes(count: padding)
        }
        finalize += paddingData
      }
      return finalize
    case .aes128Cfb:
      guard options.contains(.chunkStream) else {
        finalize = try AES.CFB.encrypt(
          Array(buffer: data),
          using: symmetricKey,
          nonce: .init(data: Array(nonce))
        )
        return finalize
      }

      guard commandCode == .udp else {
        // Transfer type stream...
        let maxAllowedMemorySize = 64 * 1024 * 1024
        guard mutableData.readableBytes + 10 <= maxAllowedMemorySize else {
          throw CodingError.payloadTooLarge
        }

        let maxPadding =
          options.contains(.chunkMasking) && options.contains(.globalPadding) ? 64 : 0

        let packetLengthDataSize = 2

        maxLength = 2048 - MemoryLayout<UInt32>.size - packetLengthDataSize - maxPadding

        while mutableData.readableBytes > 0 {
          let message =
            mutableData.readBytes(length: min(maxLength, mutableData.readableBytes)) ?? []

          let padding = nextPadding()

          var frame = Data()

          withUnsafeBytes(of: FNV1a32.hash(data: message).bigEndian) { buffPtr in
            frame.append(contentsOf: buffPtr)
          }

          frame += message

          guard packetLengthDataSize + frame.count + padding <= 2048 else {
            throw CodingError.payloadTooLarge
          }

          let frameLengthData = try prepareFrameLengthData(
            frameLength: message.count + MemoryLayout<UInt32>.size + padding,
            nonce: []
          )

          finalize += frameLengthData
          finalize += frame

          if padding > 0 {
            var paddingData = Data(repeating: .zero, count: padding)
            paddingData.withUnsafeMutableBytes {
              $0.initializeWithRandomBytes(count: padding)
            }
            finalize += paddingData
          }
        }

        finalize = try AES.CFB.encrypt(
          finalize,
          using: symmetricKey,
          nonce: .init(data: Array(nonce))
        )
        return finalize
      }

      // TODO: AES-CFB-128 UDP Frame Encoding
      return finalize
    case .aes128Gcm, .chaCha20Poly1305:
      let maxAllowedMemorySize = 64 * 1024 * 1024
      guard mutableData.readableBytes + 10 <= maxAllowedMemorySize else {
        throw CodingError.payloadTooLarge
      }

      let packetLengthSize = options.contains(.authenticatedLength) ? 18 : 2

      let maxPadding = options.contains(.chunkMasking) && options.contains(.globalPadding) ? 64 : 0

      maxLength = 2048 - 16 - packetLengthSize - maxPadding

      while mutableData.readableBytes > 0 {
        let message = mutableData.readBytes(length: min(maxLength, mutableData.readableBytes)) ?? []

        let padding = nextPadding()

        let nonce = withUnsafeBytes(of: nonceLeading.bigEndian) {
          Array($0) + Array(self.nonce.prefix(12).suffix(10))
        }

        let frame: Data
        if contentSecurity == .aes128Gcm {
          let sealedBox = try AES.GCM.seal(
            message,
            using: .init(data: symmetricKey),
            nonce: .init(data: nonce)
          )
          frame = sealedBox.ciphertext + sealedBox.tag
        } else {
          let symmetricKey = generateChaChaPolySymmetricKey(inputKeyMaterial: self.symmetricKey)
          let sealedBox = try ChaChaPoly.seal(
            message,
            using: .init(data: symmetricKey),
            nonce: .init(data: nonce)
          )
          frame = sealedBox.ciphertext + sealedBox.tag
        }

        guard packetLengthSize + frame.count + padding <= 2048 else {
          throw CodingError.payloadTooLarge
        }

        let frameLengthData = try prepareFrameLengthData(
          frameLength: frame.count + padding,
          nonce: nonce
        )

        finalize += frameLengthData
        finalize += frame

        if padding > 0 {
          var paddingData = Data(repeating: .zero, count: padding)
          paddingData.withUnsafeMutableBytes {
            $0.initializeWithRandomBytes(count: padding)
          }
          finalize += paddingData
        }

        nonceLeading &+= 1
      }

      return finalize
    default:
      throw CodingError.operationUnsupported
    }
  }

  /// Prepare frame length field data with specified frameLength and nonce.
  ///
  /// If request options contains `.authenticatedLength` then packet length data encrypt using AEAD,
  /// else if request options contains `.chunkMasking` then packet length data encrypt using SHAKE128,
  /// otherwise just return plain size data.
  /// - Parameters:
  ///   - frameLength: Frame data length.
  ///   - nonce: Nonce used to create AEAD nonce.
  /// - Returns: The encrypted frame length field data.
  private func prepareFrameLengthData(frameLength: Int, nonce: [UInt8]) throws -> Data {
    if options.contains(.authenticatedLength) {
      return try withUnsafeBytes(
        of: UInt16(frameLength - 16).bigEndian
      ) {
        var symmetricKey = KDF.deriveKey(
          inputKeyMaterial: .init(data: symmetricKey),
          info: Data("auth_len".utf8)
        )

        if contentSecurity == .aes128Gcm {
          let sealedBox = try AES.GCM.seal(
            $0,
            using: symmetricKey,
            nonce: .init(data: nonce)
          )
          return sealedBox.ciphertext + sealedBox.tag
        } else {
          symmetricKey = generateChaChaPolySymmetricKey(inputKeyMaterial: symmetricKey)
          let sealedBox = try ChaChaPoly.seal(
            $0,
            using: symmetricKey,
            nonce: .init(data: nonce)
          )
          return sealedBox.ciphertext + sealedBox.tag
        }
      }
    } else if options.contains(.chunkMasking) {
      return hasher.read(digestSize: 2).withUnsafeBytes {
        let mask = $0.load(as: UInt16.self).bigEndian
        return withUnsafeBytes(of: (mask ^ UInt16(frameLength)).bigEndian) {
          Data($0)
        }
      }
    } else {
      return withUnsafeBytes(of: UInt16(frameLength).bigEndian) {
        Data($0)
      }
    }
  }

  /// Prepare last frame data.
  ///
  /// If request should trunk stream then return encrypted empty buffer as END part data else just return empty data.
  /// - Returns: Encrypted last frame data.
  private func prepareLastFrame() throws -> Data {
    guard options.contains(.chunkStream) else {
      return .init()
    }

    return try prepareFrame(data: .init())
  }

  private func nextPadding() -> Int {
    guard options.contains(.chunkMasking) && options.contains(.globalPadding) else {
      return 0
    }
    return hasher.read(digestSize: 2).withUnsafeBytes {
      Int($0.load(as: UInt16.self).bigEndian % 64)
    }
  }
}

// VMESS request writer helpers.
extension BetterVMESSWriter {

  /// Prepare plain instruction for request.
  private func prepareInstruction0(request: VMESSRequestHead) -> ByteBuffer {
    // Should enable padding
    var buffer = ByteBuffer()
    if case .useLegacy = headEncodingStrategy {
      // TODO: Legacy HEAD Encoding
    }
    buffer.writeInteger(request.version.rawValue)
    buffer.writeBytes(nonce)
    symmetricKey.withUnsafeBytes {
      _ = buffer.writeBytes($0)
    }
    buffer.writeInteger(authenticationCode)
    buffer.writeInteger(options.rawValue)

    let padding = UInt8.random(in: 0...16)
    buffer.writeInteger((padding << 4) | contentSecurity.rawValue)
    // Write zero as keeper.
    buffer.writeInteger(UInt8.zero)
    buffer.writeInteger(request.commandCode.rawValue)

    if request.commandCode != .mux {
      buffer.writeVMESSAddress(request.address)
    }

    if padding > 0 {
      // Write random padding
      var paddingData = Array(repeating: UInt8.zero, count: Int(padding))
      paddingData.withUnsafeMutableBytes {
        $0.initializeWithRandomBytes(count: Int(padding))
      }
      buffer.writeBytes(paddingData)
    }

    buffer.writeInteger(
      buffer.withUnsafeReadableBytes {
        FNV1a32.hash(data: $0)
      }
    )
    return buffer
  }

  /// Prepare instruction part data with specified request.
  /// - Parameter request: The request object used to build instruction.
  /// - Returns: Encrypted instruction part data.
  private func prepareInstruction(request: VMESSRequestHead) throws -> Data {
    let instructionData = prepareInstruction0(request: request)

    let material = generateCmdKey(request.user)

    if case .useAEAD = headEncodingStrategy {
      let authenticatedData = try prepareAEADHeaderData(material)
      var randomPath = Array(repeating: UInt8.zero, count: 8)
      randomPath.withUnsafeMutableBytes {
        $0.initializeWithRandomBytes(count: 8)
      }

      var info = [
        Array(),
        Array(authenticatedData),
        randomPath,
      ]

      let payloadLength = UInt16(instructionData.readableBytes)
      let sealedLengthBox = try withUnsafeBytes(of: payloadLength.bigEndian) { payloadLengthData in
        info[0] = Array("VMess Header AEAD Key_Length".utf8)
        let symmetricKey = KDF.deriveKey(inputKeyMaterial: material, info: info)

        info[0] = Array("VMess Header AEAD Nonce_Length".utf8)
        return try KDF.deriveKey(inputKeyMaterial: material, info: info).withUnsafeBytes {
          try AES.GCM.seal(
            payloadLengthData,
            using: symmetricKey,
            nonce: .init(data: $0.prefix(12)),
            authenticating: authenticatedData
          )
        }
      }

      let sealedPayloadBox = try instructionData.withUnsafeReadableBytes { payloadData in
        info[0] = Array("VMess Header AEAD Key".utf8)
        let symmetricKey = KDF.deriveKey(inputKeyMaterial: material, info: info)

        info[0] = Array("VMess Header AEAD Nonce".utf8)
        return try KDF.deriveKey(inputKeyMaterial: material, info: info).withUnsafeBytes {
          try AES.GCM.seal(
            payloadData,
            using: symmetricKey,
            nonce: .init(data: $0.prefix(12)),
            authenticating: authenticatedData
          )
        }
      }

      return authenticatedData
        + sealedLengthBox.ciphertext
        + sealedLengthBox.tag
        + randomPath
        + sealedPayloadBox.ciphertext
        + sealedPayloadBox.tag
    } else {
      let date = Date() + TimeInterval.random(in: -30...30)
      let timestamp = UInt64(date.timeIntervalSince1970)

      var authenticatedData = withUnsafeBytes(of: request.user) {
        var hasher = HMAC<Insecure.MD5>(key: .init(data: $0))
        return withUnsafeBytes(of: timestamp.bigEndian) {
          hasher.update(data: $0)
          return Data(hasher.finalize())
        }
      }

      // Hash timestamp original impl of go see `client.go hashTimestamp` in v2flay.
      var hasher = Insecure.MD5()
      withUnsafeBytes(of: timestamp.bigEndian) {
        for _ in 0..<4 {
          hasher.update(bufferPointer: $0)
        }
      }

      let result = try hasher.finalize().withUnsafeBytes {
        try AES.CFB.encrypt(Array(buffer: instructionData), using: material, nonce: .init(data: $0))
      }
      authenticatedData += result
      return authenticatedData
    }
  }

  /// Generate authenticated data with specified key.
  /// - Parameter key: Input key material.
  /// - Returns: Encrypted authenticated data bytes.
  private func prepareAEADHeaderData(_ key: SymmetricKey) throws -> Data {
    let timeIntervalSince1970 = UInt64(Date().timeIntervalSince1970)
    var byteBuffer = withUnsafeBytes(of: timeIntervalSince1970.bigEndian) {
      Array($0)
    }

    var randomBytes = Array(repeating: UInt8.zero, count: 4)
    randomBytes.withUnsafeMutableBytes {
      $0.initializeWithRandomBytes(count: 4)
    }
    byteBuffer += randomBytes
    byteBuffer += withUnsafeBytes(of: CRC32.checksum(byteBuffer).bigEndian, Array.init)

    let kDFSaltConstAuthIDEncryptionKey = Data("AES Auth ID Encryption".utf8)

    let key = KDF.deriveKey(inputKeyMaterial: key, info: kDFSaltConstAuthIDEncryptionKey)

    let ciphertext = try AES.ECB.encrypt(byteBuffer, using: key)
    // We only need 16 bytes.
    return ciphertext.prefix(16)
  }
}

@available(*, unavailable)
extension BetterVMESSWriter: Sendable {}

extension ByteBuffer {

  @discardableResult
  mutating func writeVMESSAddress(_ address: NetAddress) -> Int {
    switch address {
    case .domainPort(let domain, let port):
      return self.writeInteger(UInt16(port))
        + self.writeInteger(UInt8(2))
        + self.writeInteger(UInt8(domain.utf8.count))
        + self.writeString(domain)
    case .socketAddress(.v4(let addr)):
      return self.writeInteger(addr.address.sin_port.bigEndian)
        + self.writeInteger(UInt8(1))
        + withUnsafeBytes(of: addr.address.sin_addr) { ptr in
          self.writeBytes(ptr)
        }
    case .socketAddress(.v6(let addr)):
      return self.writeInteger(addr.address.sin6_port.bigEndian)
        + self.writeInteger(UInt8(3))
        + withUnsafeBytes(of: addr.address.sin6_addr) { ptr in
          self.writeBytes(ptr)
        }
    case .socketAddress(.unixDomainSocket):
      // enforced in the channel initalisers.
      fatalError("UNIX domain sockets are not supported")
    }
  }
}

/// A `ChannelOutboundHandler` that can serialize VMESS messages.
///
/// This channel handler is used to translate messages from a series of
/// VMESS message into the VMESS wire format.
final public class VMESSEncoder<In: Equatable>: ChannelOutboundHandler {

  public typealias OutboundIn = In

  public typealias OutboundOut = ByteBuffer

  private let writer: BetterVMESSWriter<In>

  /// Creates a new instance of `VMESSEncoder`.
  /// - Parameters:
  ///   - authenticationCode: The authentication code to use to verify authenticated head message.
  ///   - contentSecurity: The security type use to control message encoding method.
  ///   - symmetricKey: SymmetricKey for encryptor.
  ///   - nonce: Nonce for encryptor.
  ///   - options: The stream options use to control data padding and mask.
  public init(
    authenticationCode: UInt8,
    contentSecurity: ContentSecurity,
    symmetricKey: SymmetricKey,
    nonce: Nonce,
    options: StreamOptions,
    commandCode: CommandCode
  ) {
    guard In.self == VMESSPart<VMESSRequestHead, ByteBuffer>.self else {
      preconditionFailure("unsupported VMESS message type \(In.self)")
    }
    self.writer = BetterVMESSWriter(
      authenticationCode: authenticationCode,
      contentSecurity: contentSecurity,
      symmetricKey: symmetricKey,
      nonce: nonce,
      options: options,
      commandCode: commandCode
    )
  }

  public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?)
  {
    do {
      let bytes = try writer.write(unwrapOutboundIn(data))
      let outboundOut = context.channel.allocator.buffer(bytes: bytes)
      context.write(wrapOutboundOut(outboundOut), promise: promise)
    } catch {
      promise?.fail(error)
    }
  }
}

@available(*, unavailable)
extension VMESSEncoder: Sendable {}
