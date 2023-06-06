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
import NESHAKE128
import NIOCore

private enum VMESSDecoderKind: Sendable {
  case request
  case response
}

private enum VMESSDecodingState {
  case headBegin
  case frameLengthBegin
  case frameDataBegin(length: Int, padding: Int)
  case complete
}

private protocol VMESSDecoderDelegate {
  mutating func didReceiveHead(_ head: Any)
  mutating func didReceiveBody(_ bytes: ByteBuffer)
  mutating func didFinishMessage()
}

private class BetterVMESSParser {

  var delegate: VMESSDecoderDelegate! = nil

  private var decodingState: VMESSDecodingState = .headBegin
  private let kind: VMESSDecoderKind
  private let authenticationCode: UInt8
  private let contentSecurity: ContentSecurity
  private let symmetricKey: SymmetricKey
  private let nonce: Nonce
  private let options: StreamOptions
  private let commandCode: CommandCode
  private let AEADFlag = true
  private var nonceLeading = UInt16.zero
  private lazy var hasher: SHAKE128 = {
    var shake128 = SHAKE128()
    nonce.withUnsafeBytes { buffPtr in
      shake128.update(data: buffPtr)
    }
    return shake128
  }()

  init(
    kind: VMESSDecoderKind,
    authenticationCode: UInt8,
    contentSecurity: ContentSecurity,
    symmetricKey: SymmetricKey,
    nonce: Nonce,
    options: StreamOptions,
    commandCode: CommandCode,
    enablePadding: Bool = false
  ) {
    self.kind = kind
    self.authenticationCode = authenticationCode
    self.symmetricKey = symmetricKey.withUnsafeBytes {
      SymmetricKey(data: Array(SHA256.hash(data: $0).prefix(16)))
    }
    self.nonce = nonce.withUnsafeBytes {
      try! Nonce(data: Array(SHA256.hash(data: $0).prefix(16)))
    }
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

  func start() {}

  func stop() {}

  func didReceiveHead(_ head: Any) {
    delegate.didReceiveHead(head)
  }

  func didReceiveBody(_ bytes: ByteBuffer) {
    delegate.didReceiveBody(bytes)
  }

  func didFinishMessage() {
    nonceLeading = 0
    decodingState = .headBegin
    if options.contains(.chunkMasking) {
      hasher = .init()
      nonce.withUnsafeBytes { buffPtr in
        hasher.update(data: buffPtr)
      }
    }
    decodingState = .complete
    delegate.didFinishMessage()
  }

  func feedInput(_ bytes: ByteBuffer?) throws -> Int {
    guard var byteBuffer = bytes else {
      didFinishMessage()
      return 0
    }

    loop: while byteBuffer.readableBytes > 0 {
      switch decodingState {
      case .headBegin:
        guard let head = try parseResponseHead(data: &byteBuffer) else {
          return 0
        }
        decodingState = .frameLengthBegin
        didReceiveHead(head)
      case .frameLengthBegin:
        guard let (frameLength, padding) = try parseLengthAndPadding(from: &byteBuffer) else {
          break loop
        }
        decodingState = .frameDataBegin(length: frameLength, padding: padding)
      case .frameDataBegin(length: let frameLength, let padding):
        guard
          let frameData = try parseFrame(
            from: &byteBuffer,
            frameLength: frameLength,
            padding: padding
          )
        else {
          break loop
        }
        didReceiveBody(ByteBuffer(bytes: frameData))
        decodingState = .frameLengthBegin
      case .complete:
        break loop
      }
    }

    return byteBuffer.readerIndex - bytes!.readerIndex
  }

  private func parseResponseHead(data: inout ByteBuffer) throws -> VMESSResponseHead? {
    guard AEADFlag else {
      return try parseHeadFromPlainMessage(&data)
    }
    return try parseHeadFromAEADMessage(&data)
  }

  /// Parse VMESS response head part from AEAD encrypted data.
  private func parseHeadFromAEADMessage(_ message: inout ByteBuffer) throws -> VMESSResponseHead? {
    let kDFSaltConstAEADRespHeaderLenKey = Data("AEAD Resp Header Len Key".utf8)
    let kDFSaltConstAEADRespHeaderLenIV = Data("AEAD Resp Header Len IV".utf8)

    var symmetricKey = KDF.deriveKey(
      inputKeyMaterial: .init(data: self.symmetricKey),
      info: kDFSaltConstAEADRespHeaderLenKey
    )
    var nonce = KDF.deriveKey(
      inputKeyMaterial: .init(data: self.nonce),
      info: kDFSaltConstAEADRespHeaderLenIV,
      outputByteCount: 12
    ).withUnsafeBytes {
      Array($0)
    }

    // 2 byte packet length data and 16 overhead
    var byteCountNeeded = 18
    guard var combined = message.readBytes(length: byteCountNeeded) else {
      return nil
    }

    combined = nonce + combined
    let ciphertextLengthData = try AES.GCM.open(.init(combined: combined), using: symmetricKey)
    assert(ciphertextLengthData.count == 2)

    let ciphertextLength = ciphertextLengthData.withUnsafeBytes {
      $0.load(as: UInt16.self).bigEndian
    }
    byteCountNeeded = Int(ciphertextLength) + 16
    guard let ciphertextAndTag = message.readBytes(length: byteCountNeeded) else {
      // return nil to tell decoder we need more data.
      return nil
    }

    let kDFSaltConstAEADRespHeaderPayloadKey = Data("AEAD Resp Header Key".utf8)
    let kDFSaltConstAEADRespHeaderPayloadIV = Data("AEAD Resp Header IV".utf8)

    symmetricKey = KDF.deriveKey(
      inputKeyMaterial: .init(data: self.symmetricKey),
      info: kDFSaltConstAEADRespHeaderPayloadKey
    )
    nonce = KDF.deriveKey(
      inputKeyMaterial: .init(data: self.nonce),
      info: kDFSaltConstAEADRespHeaderPayloadIV,
      outputByteCount: 12
    ).withUnsafeBytes {
      Array($0)
    }
    combined = nonce + ciphertextAndTag
    let headPartData = try AES.GCM.open(.init(combined: combined), using: symmetricKey)
    assert(headPartData.count >= 4)

    return try parseHeadFromData(headPartData)
  }

  private func parseHeadFromPlainMessage(_ message: inout ByteBuffer) throws -> VMESSResponseHead? {
    var byteCountNeeded = 4
    guard message.readableBytes >= byteCountNeeded,
      let commandLength = message.getInteger(at: message.readerIndex &+ 3, as: UInt8.self)
    else {
      return nil
    }

    byteCountNeeded += Int(commandLength)
    guard message.readableBytes >= byteCountNeeded else {
      return nil
    }
    // Force unwrapping is ok as we have already checked readableBytes.
    let headPartData = Data(message.readBytes(length: byteCountNeeded)!)
    return try parseHeadFromData(headPartData)
  }

  private func parseHeadFromData(_ headPartData: Data) throws -> VMESSResponseHead {
    var headPartData = headPartData

    guard authenticationCode == headPartData.removeFirst() else {
      // Unexpected response header
      throw VMESSError.authenticationFailure
    }

    let options = StreamOptions.init(rawValue: headPartData.removeFirst())

    let commandCode = headPartData.removeFirst()

    var head = VMESSResponseHead.init(
      authenticationCode: authenticationCode,
      options: options,
      commandCode: .init(rawValue: commandCode),
      command: nil
    )

    guard commandCode != 0 else {
      return head
    }

    headPartData.removeFirst()

    // We don't care about command there just read it if possible.
    if let command = try? parseCommand(code: commandCode, data: headPartData) {
      head.command = command
    }
    return head
  }

  /// Parse command from data with specified commandCode.
  private func parseCommand(code: UInt8, data: Data) throws -> ResponseCommand? {
    var mutableData = data

    let commandLength = Int(mutableData.removeFirst())

    guard commandLength != 0 else {
      return nil
    }

    guard mutableData.count > 4, mutableData.count >= commandLength else {
      throw CodingError.incorrectDataSize
    }

    let actualAuthCode = mutableData.prefix(upTo: 4).withUnsafeBytes {
      $0.load(as: UInt32.self).bigEndian
    }

    let expectedAuthCode = commonFNV1a(mutableData[4...])

    if actualAuthCode != expectedAuthCode {
      throw VMESSError.authenticationFailure
    }

    switch code {
    case 1:
      mutableData = mutableData.dropFirst(4)
      guard !mutableData.isEmpty else {
        throw CodingError.incorrectDataSize
      }

      let addressLength = Int(mutableData.removeFirst())
      guard mutableData.count >= addressLength else {
        throw CodingError.incorrectDataSize
      }

      var address: NetAddress?
      // Parse address
      if addressLength > 0 {
        address = try parseAddress(data: mutableData.prefix(addressLength))
        mutableData = mutableData.dropFirst(4)
      }

      // Parse port
      guard mutableData.count >= 2 else {
        throw CodingError.incorrectDataSize
      }
      let port = mutableData.prefix(2).withUnsafeBytes {
        $0.load(as: in_port_t.self)
      }
      if let v = address {
        switch v {
        case .domainPort(let host, _):
          address = .domainPort(host: host, port: Int(port))
        case .socketAddress(let socketAddress):
          var socketAddress = socketAddress
          socketAddress.port = Int(port)
          address = .socketAddress(socketAddress)
        }
      }
      mutableData = mutableData.dropFirst(2)

      // Parse ID
      guard mutableData.count >= MemoryLayout<UUID>.size else {
        throw CodingError.incorrectDataSize
      }
      let id = mutableData.prefix(MemoryLayout<UUID>.size).withUnsafeBytes {
        $0.load(as: UUID.self)
      }
      mutableData = mutableData.dropFirst(MemoryLayout<UUID>.size)

      // Parse countOfAlterIDs
      guard mutableData.count >= 2 else {
        throw CodingError.incorrectDataSize
      }
      let countOfAlterIDs = mutableData.prefix(2).withUnsafeBytes {
        $0.load(as: UInt16.self).bigEndian
      }
      mutableData = mutableData.dropFirst(2)

      // Parse level
      guard mutableData.count >= 2 else {
        throw CodingError.incorrectDataSize
      }
      let level = mutableData.prefix(2).withUnsafeBytes {
        UInt32($0.load(as: UInt16.self))
      }
      mutableData = mutableData.dropFirst(2)

      // Parse valid time
      guard mutableData.count >= 1 else {
        throw CodingError.incorrectDataSize
      }

      return SwitchAccountCommand.init(
        id: id,
        level: level,
        countOfAlterIDs: countOfAlterIDs,
        address: address,
        validMin: mutableData.removeFirst()
      )
    default:
      throw VMESSError.operationUnsupported
    }
  }

  /// Parse address with specified data.
  private func parseAddress(data: Data) throws -> NetAddress {
    guard let string = String(data: data, encoding: .utf8), !string.isEmpty else {
      throw SocketAddressError.unsupported
    }

    guard string.isIPAddress() else {
      return .domainPort(host: string, port: 0)
    }

    return .socketAddress(try .init(ipAddress: string, port: 0))
  }

  /// Parse frame length and padding from buffer.
  ///
  /// Return nil if need more data else return parsed length and padding.
  private func parseLengthAndPadding(from buffer: inout ByteBuffer) throws -> (Int, Int)? {
    var padding = 0

    switch contentSecurity {
    case .none:
      guard options.contains(.chunkStream) else {
        return (buffer.readableBytes, padding)
      }
      if commandCode == .udp {
        padding = nextPadding()

        guard let frameLength = try parseLength0(from: &buffer) else {
          return nil
        }
        return (frameLength, padding)
      } else {
        guard let frameLength = try parseLength0(from: &buffer) else {
          return nil
        }
        return (frameLength, padding)
      }
    case .encryptByAES128GCM, .encryptByChaCha20Poly1305:
      // Both `AES.GCM.tagSize` and `ChaChaPoly.tagSize` are 16.
      let tagDataLength = 16
      var frameLengthDataLength = MemoryLayout<UInt16>.size

      if options.contains(.authenticatedLength) {
        frameLengthDataLength += tagDataLength
      }

      // Buffer is not enough to decode frame length, return nil to waiting for more data.
      guard var frameLengthData = buffer.readSlice(length: frameLengthDataLength) else {
        return nil
      }

      padding = nextPadding()

      guard options.contains(.authenticatedLength) else {
        guard let frameLength = try parseLength0(from: &frameLengthData) else {
          // We have already checked that data is enough to read frame length,
          // so there we should throw error instead of return nil.
          throw CodingError.failedToParseDataSize
        }
        return (frameLength, padding)
      }

      var symmetricKey = KDF.deriveKey(
        inputKeyMaterial: .init(data: symmetricKey),
        info: Data("auth_len".utf8)
      )

      let nonce = withUnsafeBytes(of: nonceLeading.bigEndian) {
        Array($0) + Array(self.nonce.prefix(12).suffix(10))
      }

      if contentSecurity == .encryptByAES128GCM {
        let sealedBox = try AES.GCM.SealedBox(combined: nonce + Array(buffer: frameLengthData))
        let frameLength = try AES.GCM.open(sealedBox, using: symmetricKey).withUnsafeBytes {
          $0.load(as: UInt16.self).bigEndian + UInt16(tagDataLength)
        }
        return (Int(frameLength), padding)
      } else {
        symmetricKey = generateChaChaPolySymmetricKey(inputKeyMaterial: symmetricKey)
        let sealedBox = try ChaChaPoly.SealedBox(combined: nonce + Array(buffer: frameLengthData))
        let frameLength = try ChaChaPoly.open(sealedBox, using: symmetricKey).withUnsafeBytes {
          $0.load(as: UInt16.self).bigEndian + UInt16(tagDataLength)
        }
        return (Int(frameLength), padding)
      }
    default:
      throw CodingError.operationUnsupported
    }
  }

  private func parseLength0(from buffer: inout ByteBuffer) throws -> Int? {
    guard options.contains(.chunkMasking) else {
      guard let frameLength = buffer.readInteger(as: UInt16.self) else {
        return nil
      }
      return Int(frameLength)
    }

    guard let l = buffer.readInteger(as: UInt16.self) else {
      return nil
    }

    let frameLength = hasher.read(digestSize: 2).withUnsafeBytes {
      let mask = $0.load(as: UInt16.self).bigEndian
      return mask ^ l
    }
    return Int(frameLength)
  }

  /// Parse frame from buffer with specified frameLength and padding..
  private func parseFrame(from buffer: inout ByteBuffer, frameLength: Int, padding: Int) throws
    -> Data?
  {
    switch contentSecurity {
    case .none:
      guard options.contains(.chunkStream) else {
        guard let message = buffer.readBytes(length: frameLength) else {
          return nil
        }
        return Data(message)
      }

      guard commandCode == .udp else {
        // Transfer type stream...
        guard let message = buffer.readBytes(length: frameLength) else {
          return nil
        }
        return Data(message)
      }
      // TODO: Parse UDP Frame
      return nil
    case .encryptByAES128GCM, .encryptByChaCha20Poly1305:
      // Tag for AES-GCM or ChaCha20-Poly1305 are both 16.
      guard frameLength != 16 + padding else {
        throw CryptoKitError.authenticationFailure
      }

      guard let message = buffer.readBytes(length: frameLength) else {
        return nil
      }

      let nonce = withUnsafeBytes(of: nonceLeading.bigEndian) {
        Array($0) + Array(self.nonce.prefix(12).suffix(10))
      }

      // Remove random padding bytes.
      let combined = nonce + (message.dropLast(padding))

      var frame: Data
      if contentSecurity == .encryptByAES128GCM {
        frame = try AES.GCM.open(.init(combined: combined), using: .init(data: symmetricKey))
      } else {
        let symmetricKey = generateChaChaPolySymmetricKey(inputKeyMaterial: symmetricKey)
        frame = try ChaChaPoly.open(.init(combined: combined), using: symmetricKey)
      }

      nonceLeading &+= 1
      return frame
    default:
      throw CodingError.operationUnsupported
    }
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
extension BetterVMESSParser: Sendable {}

public typealias VMESSClientResponsePart = VMESSPart<VMESSResponseHead, ByteBuffer>

/// A `ChannelInboundHandler` that parses VMESS style messages, converting them from
/// unstructured bytes to a sequence of VMESS messages.
///
/// The `VMESSDecoder` is a generic channel handler which can produce messages in
/// the form of `VMESSClientResponsePart`,
/// it produces messages that correspond to the semantic units of VMESS produced by
/// the remote peer.
final public class VMESSDecoder<Out>: ByteToMessageDecoder, VMESSDecoderDelegate {

  public typealias InboundOut = Out

  private var context: ChannelHandlerContext?

  private let parser: BetterVMESSParser
  private let kind: VMESSDecoderKind
  private var stopParsing = false

  /// Creates a new instance of `VMESSDecoder`.
  /// - Parameters:
  ///   - authenticationCode: The authentication code to use to verify authenticated head message.
  ///   - contentSecurity: The security type use to control message decoding method.
  ///   - symmetricKey: SymmetricKey for decriptor.
  ///   - nonce: Nonce for decryptor.
  ///   - options: The stream options use to control data padding and mask.
  public init(
    authenticationCode: UInt8,
    contentSecurity: ContentSecurity,
    symmetricKey: SymmetricKey,
    nonce: Nonce,
    options: StreamOptions,
    commandCode: CommandCode
  ) {
    if Out.self == VMESSPart<VMESSResponseHead, ByteBuffer>.self {
      self.kind = .response
    } else {
      preconditionFailure("unsupported VMESS message type \(Out.self)")
    }
    self.parser = BetterVMESSParser(
      kind: kind,
      authenticationCode: authenticationCode,
      contentSecurity: contentSecurity,
      symmetricKey: symmetricKey,
      nonce: nonce,
      options: options,
      commandCode: commandCode
    )
  }

  func didReceiveHead(_ head: Any) {
    let message: NIOAny?

    switch kind {
    case .request:
      // TODO: Receive VMESS request head frame
      message = nil
      break
    case .response:
      guard let head = head as? VMESSResponseHead else {
        stopParsing = true
        context?.fireErrorCaught(CodingError.typeMismatch(VMESSResponseHead.self, head))
        return
      }
      message = NIOAny(VMESSPart<VMESSResponseHead, ByteBuffer>.head(head))
    }

    guard let message else {
      return
    }
    context?.fireChannelRead(message)
  }

  func didReceiveBody(_ bytes: ByteBuffer) {
    switch kind {
    case .request:
      // TODO: Receive VMESS request body frames
      break
    case .response:
      context?.fireChannelRead(NIOAny(VMESSPart<VMESSResponseHead, ByteBuffer>.body(bytes)))
    }
  }

  func didFinishMessage() {
    switch kind {
    case .request:
      // TODO: Receive VMESS request end
      break
    case .response:
      context?.fireChannelRead(NIOAny(VMESSPart<VMESSResponseHead, ByteBuffer>.end))
    }
    stopParsing = true
  }

  public func decoderAdded(context: ChannelHandlerContext) {
    parser.delegate = self
    parser.start()
  }

  public func decoderRemoved(context: ChannelHandlerContext) {
    parser.stop()
    parser.delegate = nil
  }

  private func feedEOF(context: ChannelHandlerContext) throws {
    self.context = context
    defer {
      self.context = nil
    }
    _ = try parser.feedInput(nil)
  }

  private func feedInput(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws {
    self.context = context
    defer {
      self.context = nil
    }
    let consumed = try parser.feedInput(buffer)
    buffer.moveReaderIndex(forwardBy: consumed)
  }

  public func decode(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws
    -> DecodingState
  {
    if !stopParsing {
      try feedInput(context: context, buffer: &buffer)
    }
    return .needMoreData
  }

  public func decodeLast(context: ChannelHandlerContext, buffer: inout ByteBuffer, seenEOF: Bool)
    throws -> DecodingState
  {
    if !stopParsing {
      while buffer.readableBytes > 0,
        case .continue = try decode(context: context, buffer: &buffer)
      {}
      if seenEOF {
        try feedEOF(context: context)
      }
    }
    if buffer.readableBytes > 0 && !seenEOF {
      // We only do this if we haven't seen EOF because the left-overs strategy must only be invoked when we're
      // sure that this is the completion of an upgrade.
      context.fireErrorCaught(ByteToMessageDecoderError.leftoverDataWhenDone(buffer))
    }
    return .needMoreData
  }
}

@available(*, unavailable)
extension VMESSDecoder: Sendable {}
