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
import NESHAKE128
import NIOCore

private enum VMESSEncodeKind: Sendable {
  case request
  case response
}

private class BetterVMESSWriter<In> where In: Equatable {

  private let kind: VMESSEncodeKind
  private let authenticationCode: UInt8
  private let contentSecurity: ContentSecurity
  private let symmetricKey: SymmetricKey
  private let nonce: Nonce
  private let options: StreamOptions
  private let commandCode: CommandCode
  private let AEADFlag: Bool = true
  private lazy var hasher: SHAKE128 = {
    var shake128 = SHAKE128()
    nonce.withUnsafeBytes { buffPtr in
      shake128.update(data: buffPtr)
    }
    return shake128
  }()
  private var nonceLeading = UInt16.zero

  init(
    authenticationCode: UInt8,
    contentSecurity: ContentSecurity,
    symmetricKey: SymmetricKey,
    nonce: Nonce,
    options: StreamOptions,
    commandCode: CommandCode,
    enablePadding: Bool = false
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
    case .encryptByAES128GCM, .encryptByChaCha20Poly1305:
      options.insert(.chunkMasking)
      options.insert(.globalPadding)
      self.contentSecurity = contentSecurity
    case .none:
      options.insert(.chunkMasking)
      if enablePadding {
        options.insert(.globalPadding)
      }
      self.contentSecurity = contentSecurity
    case .legacy:
      if options.contains(.chunkMasking) && enablePadding {
        options.insert(.globalPadding)
      }
      self.contentSecurity = contentSecurity
    case .automatically:
      options.insert(.globalPadding)
      self.contentSecurity = contentSecurity
    case .zero:
      self.contentSecurity = .none
      if options.contains(.chunkMasking) && enablePadding {
        options.insert(.globalPadding)
      }
      options.remove(.chunkStream)
      options.remove(.chunkMasking)
    default:
      preconditionFailure("unsupported VMESS message content security")
    }
    self.options = options
    self.commandCode = commandCode
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
}

// VMESS request writer helpers.
extension BetterVMESSWriter {

  /// Prepare plain instruction for request.
  private func prepareInstruction0(request: VMESSRequestHead) -> ByteBuffer {
    // Should enable padding
    var buffer = ByteBuffer()
    if !AEADFlag {
      // TODO: head
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
      switch request.address {
      case .domainPort(let domain, let port):
        buffer.writeInteger(UInt16(port))
        buffer.writeInteger(UInt8(2))
        buffer.writeInteger(UInt8(domain.utf8.count))
        buffer.writeString(domain)
      case .socketAddress(.v4(let addr)):
        buffer.writeInteger(addr.address.sin_port.bigEndian)
        buffer.writeInteger(UInt8(1))
        withUnsafeBytes(of: addr.address.sin_addr) { ptr in
          _ = buffer.writeBytes(ptr)
        }
      case .socketAddress(.v6(let addr)):
        buffer.writeInteger(addr.address.sin6_port.bigEndian)
        buffer.writeInteger(UInt8(3))
        withUnsafeBytes(of: addr.address.sin6_addr) { ptr in
          _ = buffer.writeBytes(ptr)
        }
      case .socketAddress(.unixDomainSocket):
        // enforced in the channel initalisers.
        fatalError("UNIX domain sockets are not supported")
      }
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
        commonFNV1a($0)
      }
    )
    return buffer
  }

  /// Prepare instruction part data with specified request.
  /// - Parameter request: The request object used to build instruction.
  /// - Returns: Encrypted instruction part data.
  private func prepareInstruction(request: VMESSRequestHead) throws -> Data {
    let instructionData = prepareInstruction0(request: request)

    let inputKeyMaterial = generateCmdKey(request.user)

    if AEADFlag {
      let authenticatedData = try prepareAuthenticationData(inputKeyMaterial)
      var randomPath = Data(repeating: UInt8.zero, count: 8)
      randomPath.withUnsafeMutableBytes {
        $0.initializeWithRandomBytes(count: 8)
      }

      var info = [
        Data(),
        authenticatedData,
        randomPath,
      ]

      let sealedLengthBox: AES.GCM.SealedBox = try withUnsafeBytes(
        of: UInt16(instructionData.readableBytes).bigEndian
      ) {
        let kDFSaltConstVMessHeaderPayloadLengthAEADKey = Data("VMess Header AEAD Key_Length".utf8)
        let kDFSaltConstVMessHeaderPayloadLengthAEADIV = Data("VMess Header AEAD Nonce_Length".utf8)

        info[0] = kDFSaltConstVMessHeaderPayloadLengthAEADKey
        let symmetricKey = KDF.deriveKey(inputKeyMaterial: inputKeyMaterial, info: info)

        info[0] = kDFSaltConstVMessHeaderPayloadLengthAEADIV
        let nonce = try KDF.deriveKey(
          inputKeyMaterial: inputKeyMaterial,
          info: info,
          outputByteCount: 12
        )
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

      let sealedPayloadBox: AES.GCM.SealedBox = try instructionData.withUnsafeReadableBytes {

        let kDFSaltConstVMessHeaderPayloadAEADKey = Data("VMess Header AEAD Key".utf8)
        let kDFSaltConstVMessHeaderPayloadAEADIV = Data("VMess Header AEAD Nonce".utf8)

        info[0] = kDFSaltConstVMessHeaderPayloadAEADKey
        let symmetricKey = KDF.deriveKey(inputKeyMaterial: inputKeyMaterial, info: info)

        info[0] = kDFSaltConstVMessHeaderPayloadAEADIV
        let nonce = try KDF.deriveKey(
          inputKeyMaterial: inputKeyMaterial,
          info: info,
          outputByteCount: 12
        )
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
      var result = Data(repeating: 0, count: instructionData.readableBytes)
      try instructionData.withUnsafeReadableBytes { inPtr in
        try result.withUnsafeMutableBytes { dataOut in
          try commonAESCFB128Encrypt(
            key: inputKeyMaterial,
            nonce: hasher.finalize(),
            dataIn: inPtr,
            dataOut: dataOut,
            dataOutAvailable: instructionData.readableBytes
          )
        }
      }
      authenticatedData += result
      return authenticatedData
    }
  }

  /// Generate authenticated data with specified key.
  /// - Parameter key: Input key material.
  /// - Returns: Encrypted authenticated data bytes.
  private func prepareAuthenticationData(_ key: SymmetricKey) throws -> Data {
    var byteBuffer = withUnsafeBytes(
      of: UInt64(Date().timeIntervalSince1970).bigEndian,
      Array.init
    )
    var randomBytes = Array(repeating: UInt8.zero, count: 4)
    randomBytes.withUnsafeMutableBytes {
      $0.initializeWithRandomBytes(count: 4)
    }
    byteBuffer += randomBytes
    byteBuffer += withUnsafeBytes(of: CRC32.checksum(byteBuffer).bigEndian, Array.init)

    let kDFSaltConstAuthIDEncryptionKey = Data("AES Auth ID Encryption".utf8)

    let key = KDF.deriveKey(inputKeyMaterial: key, info: kDFSaltConstAuthIDEncryptionKey)

    var result = Data(repeating: 0, count: byteBuffer.count + 16)

    try byteBuffer.withUnsafeBytes { inPtr in
      try result.withUnsafeMutableBytes { outPtr in
        try commonAESEncrypt(
          key: key,
          dataIn: inPtr,
          dataOut: outPtr,
          dataOutAvailable: byteBuffer.count + 16
        )
      }
    }

    return result.prefix(16)
  }

  /// Prepare frame data with specified data.
  /// - Parameter data: Original data.
  /// - Returns: Encrypted frame data.
  private func prepareFrame(data: ByteBuffer) throws -> Data {
    var mutableData = data

    let maxLength: Int

    switch contentSecurity {
    case .encryptByAES128GCM, .encryptByChaCha20Poly1305:
      var frameBuffer = Data()
      // TCP
      let maxAllowedMemorySize = 64 * 1024 * 1024
      guard mutableData.readableBytes + 10 <= maxAllowedMemorySize else {
        throw CodingError.incorrectDataSize
      }

      let overhead = 16

      let packetLengthSize = options.contains(.authenticatedLength) ? 2 + overhead : 2

      let maxPadding = options.contains(.chunkMasking) && options.contains(.globalPadding) ? 64 : 0

      maxLength = 2048 - overhead - packetLengthSize - maxPadding

      while mutableData.readableBytes > 0 {
        let message = mutableData.readBytes(length: min(maxLength, mutableData.readableBytes)) ?? []

        let padding = nextPadding()

        let nonce = withUnsafeBytes(of: nonceLeading.bigEndian) {
          Array($0) + Array(self.nonce.prefix(12).suffix(10))
        }

        let frame: Data
        if contentSecurity == .encryptByAES128GCM {
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

        var paddingData = Data(repeating: .zero, count: padding)
        paddingData.withUnsafeMutableBytes {
          $0.initializeWithRandomBytes(count: padding)
        }

        frameBuffer += frameLengthData
        frameBuffer += frame
        frameBuffer += paddingData

        nonceLeading &+= 1
      }

      return frameBuffer
    case .none:
      guard options.contains(.chunkStream) else {
        return Data(Array(buffer: mutableData))
      }

      guard commandCode == .udp else {
        // Transfer type stream...
        var frameBuffer = Data()
        maxLength = 8192
        while mutableData.readableBytes > 0 {
          let sliceLength = min(maxLength, mutableData.readableBytes)
          let slice = mutableData.readBytes(length: sliceLength)!
          let frameLengthData = try prepareFrameLengthData(frameLength: sliceLength, nonce: [])
          frameBuffer += frameLengthData
          frameBuffer += slice
        }
        return frameBuffer
      }

      var frameBuffer = Data()
      maxLength = 64 * 1024 * 1024
      guard mutableData.readableBytes <= maxLength else {
        throw CodingError.incorrectDataSize
      }
      let encryptedSize = mutableData.readableBytes

      let padding = nextPadding()

      guard 2 + encryptedSize + padding <= 2048 else {
        throw CodingError.incorrectDataSize
      }
      frameBuffer.append(
        try prepareFrameLengthData(frameLength: encryptedSize + padding, nonce: [])
      )
      frameBuffer.append(contentsOf: Array(buffer: mutableData))
      if padding > 0 {
        var paddingData = Data(repeating: .zero, count: padding)
        paddingData.withUnsafeMutableBytes { buffPtr in
          buffPtr.initializeWithRandomBytes(count: padding)
        }
        frameBuffer.append(paddingData)
      }
      return frameBuffer
    case .legacy:
      // TODO: AGS-CFB-128
      assertionFailure()
      return Data()
    default:
      preconditionFailure("unsupported VMESS message content security")
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

        if contentSecurity == .encryptByAES128GCM {
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

@available(*, unavailable)
extension BetterVMESSWriter: Sendable {}

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
