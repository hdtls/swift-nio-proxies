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

public enum VMESSEncodeKind: Sendable {
  case request
  case response
}

final public class VMESSEncoder<In>: ChannelOutboundHandler {

  public typealias OutboundIn = In

  private let kind: VMESSEncodeKind
  private let authenticationCode: UInt8
  private let contentSecurity: ContentSecurity
  private let symmetricKey: [UInt8]
  private let nonce: [UInt8]
  private var options: StreamOptions
  private let AEADFlag: Bool = true
  private lazy var hasher: SHAKE128 = {
    var shake128 = SHAKE128()
    shake128.update(data: nonce)
    return shake128
  }()
  private var nonceLeading = UInt16.zero

  public init(
    authenticationCode: UInt8,
    contentSecurity: ContentSecurity,
    symmetricKey: [UInt8],
    nonce: [UInt8],
    options: StreamOptions
  ) {
    if In.self == VMESSPart<VMESSRequestHead, ByteBuffer>.self {
      self.kind = .request
    } else {
      preconditionFailure("unknown VMESS message type \(In.self)")
    }
    self.authenticationCode = authenticationCode
    switch contentSecurity {
    case .encryptByAES128GCM, .encryptByChaCha20Poly1305:
      self.contentSecurity = contentSecurity
    default:
      preconditionFailure("unsupported VMESS message encryption algorithm")
    }
    self.symmetricKey = symmetricKey
    self.nonce = nonce
    var options = options
    switch contentSecurity {
    case .legacy:
      break
    case .encryptByAES128GCM, .encryptByChaCha20Poly1305:
      options.insert(.masking)
      options.insert(.padding)
    case .none:
      options.insert(.masking)
    case .zero:
      options.remove(.chunked)
      options.remove(.masking)
    default:
      break
    }
    self.options = options
  }

  public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?)
  {
    do {
      switch kind {
      case .request:
        let part = unwrapOutboundIn(data) as! VMESSPart<VMESSRequestHead, ByteBuffer>
        let bytes: Data
        switch part {
        case .head(let headT):
          bytes = try prepareHeadPart(request: headT)
        case .body(let bodyT):
          bytes = try prepareFrame(data: bodyT)
        case .end:
          bytes = try prepareLastFrame()
        }
        let byteBuffer = context.channel.allocator.buffer(bytes: bytes)
        context.write(NIOAny(byteBuffer), promise: promise)
      case .response:
        promise?.fail(CodingError.operationUnsupported)
      }
    } catch {
      promise?.fail(error)
    }
  }

  /// Prepare HEAD part data for request.
  ///
  /// If use AEAD to encrypt request then the HEAD part only contains instruction else HEAD part contains
  /// authentication info and instruction two parts.
  /// - Returns: Encrypted HEAD part data.
  private func prepareHeadPart(request: VMESSRequestHead) throws -> Data {
    let date = Date() + TimeInterval.random(in: -30...30)
    let timestamp = UInt64(date.timeIntervalSince1970)

    var result = Data()
    result += try prepareAuthenticationInfoPart(request: request, timestamp: timestamp)
    result += try prepareInstructionPart(request: request, timestamp: timestamp)
    return result
  }

  /// Prepare HEAD authentication info part data with specified request and timestamp.
  ///
  /// If use AEAD to encrypt request just return empty data instead.
  private func prepareAuthenticationInfoPart(request: VMESSRequestHead, timestamp: UInt64) throws
    -> Data
  {
    guard !AEADFlag else {
      return .init()
    }

    return withUnsafeBytes(of: request.user) {
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
  private func prepareInstructionPart(request: VMESSRequestHead, timestamp: UInt64) throws -> Data {
    // Should enable padding
    var buffer = ByteBuffer()
    buffer.writeInteger(request.version.rawValue)
    buffer.writeBytes(nonce)
    buffer.writeBytes(symmetricKey)
    buffer.writeInteger(authenticationCode)
    buffer.writeInteger(options.rawValue)

    let padding = UInt8.random(in: 0...16)
    buffer.writeInteger((padding << 4) | contentSecurity.rawValue)
    // Write zero as keeper.
    buffer.writeInteger(UInt8(0))
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

    let inputKeyMaterial = generateCmdKey(request.user)
    if AEADFlag {
      let authenticatedData = try generateAuthenticatedData(inputKeyMaterial)
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
        of: UInt16(buffer.readableBytes).bigEndian
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

      let sealedPayloadBox: AES.GCM.SealedBox = try buffer.withUnsafeReadableBytes {

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
      // Hash timestamp original impl of go see `client.go hashTimestamp` in v2flay.
      var hasher = Insecure.MD5()
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
  private func generateAuthenticatedData(_ key: SymmetricKey) throws -> Data {
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

    // TCP
    let maxAllowedMemorySize = 64 * 1024 * 1024
    guard data.readableBytes + 10 <= maxAllowedMemorySize else {
      throw CodingError.incorrectDataSize
    }

    let overhead = contentSecurity.overhead

    let packetLengthSize = options.contains(.authenticatedLength) ? 2 + overhead : 2

    let maxPadding = options.shouldPadding ? 64 : 0

    let maxLength = 2048 - overhead - packetLengthSize - maxPadding

    var frameBuffer: Data = .init()

    while mutableData.readableBytes > 0 {
      let message = mutableData.readBytes(length: min(maxLength, mutableData.readableBytes)) ?? []

      var padding = 0
      if options.shouldPadding {
        hasher.read(digestSize: 2).withUnsafeBytes {
          padding = Int($0.load(as: UInt16.self).bigEndian % 64)
        }
      }

      let nonce = withUnsafeBytes(of: nonceLeading.bigEndian) {
        Array($0) + Array(self.nonce.prefix(12).suffix(10))
      }

      var frame: Data = .init()

      if contentSecurity == .encryptByAES128GCM {
        let sealedBox = try AES.GCM.seal(
          message,
          using: .init(data: symmetricKey),
          nonce: .init(data: nonce)
        )
        frame = sealedBox.ciphertext + sealedBox.tag
      } else {
        let symmetricKey = generateChaChaPolySymmetricKey(inputKeyMaterial: symmetricKey)
        let sealedBox = try ChaChaPoly.seal(
          message,
          using: symmetricKey,
          nonce: .init(data: nonce)
        )
        frame = sealedBox.ciphertext + sealedBox.tag
      }

      guard packetLengthSize + frame.count + padding <= 2048 else {
        throw CodingError.incorrectDataSize
      }

      let frameLengthData = try prepareFrameLengthData(
        frameLength: frame.count + padding,
        nonce: nonce
      )

      frameBuffer.append(frameLengthData)
      frameBuffer.append(frame)

      var paddingData = Array(repeating: UInt8.zero, count: padding)
      paddingData.withUnsafeMutableBytes {
        $0.initializeWithRandomBytes(count: padding)
      }
      frameBuffer.append(contentsOf: paddingData)

      nonceLeading &+= 1
    }

    return frameBuffer
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
        of: UInt16(frameLength - contentSecurity.overhead).bigEndian
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
          symmetricKey = symmetricKey.withUnsafeBytes {
            generateChaChaPolySymmetricKey(inputKeyMaterial: $0)
          }
          let sealedBox = try ChaChaPoly.seal(
            $0,
            using: symmetricKey,
            nonce: .init(data: nonce)
          )
          return sealedBox.ciphertext + sealedBox.tag
        }
      }
    } else if options.contains(.masking) {
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
    guard options.contains(.chunked) else {
      return .init()
    }

    return try prepareFrame(data: .init())
  }
}

@available(*, unavailable)
extension VMESSEncoder: Sendable {}
