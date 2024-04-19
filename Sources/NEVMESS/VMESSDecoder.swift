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
  private let contentSecurity: ContentSecurity
  private let symmetricKey: SymmetricKey
  private let nonce: [UInt8]
  private let options: StreamOptions
  private let commandCode: CommandCode
  private var nonceLeading = UInt16.zero
  private let headDecryptionStrategy: ResponseHeadDecryptionStrategy
  private lazy var hasher: SHAKE128 = {
    var shake128 = SHAKE128()
    nonce.withUnsafeBytes { buffPtr in
      shake128.update(data: buffPtr)
    }
    return shake128
  }()

  init(
    kind: VMESSDecoderKind,
    contentSecurity: ContentSecurity,
    symmetricKey: SymmetricKey,
    nonce: [UInt8],
    options: StreamOptions,
    commandCode: CommandCode,
    headDecryptionStrategy: ResponseHeadDecryptionStrategy
  ) {
    self.kind = kind
    self.symmetricKey = symmetricKey.withUnsafeBytes {
      SymmetricKey(data: Array(SHA256.hash(data: $0).prefix(16)))
    }
    self.nonce = Array(SHA256.hash(data: nonce).prefix(16))
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
    self.headDecryptionStrategy = headDecryptionStrategy
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
        let parseStrategy = ResponseHeadParseStrategy(
          symmetricKey: symmetricKey,
          nonce: nonce,
          decryptionStrategy: headDecryptionStrategy
        )
        guard let (head, consumed) = try parseStrategy.parse(byteBuffer) else {
          return 0
        }
        byteBuffer.moveReaderIndex(forwardBy: consumed)
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
        didReceiveBody(frameData)
        decodingState = .frameLengthBegin
      case .complete:
        break loop
      }
    }

    return byteBuffer.readerIndex - bytes!.readerIndex
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
      }
      guard let frameLength = try parseLength(from: &buffer) else {
        return nil
      }
      return (frameLength, padding)
    case .aes128Cfb:
      guard options.contains(.chunkStream) else {
        return (buffer.readableBytes, padding)
      }

      // We can't actual read payload length data there, it will cause frame decrypt failed.
      let payloadLengthDataSize = MemoryLayout<UInt16>.size
      let startIndex = buffer.readerIndex
      guard var message = buffer.getSlice(at: startIndex, length: payloadLengthDataSize) else {
        return nil
      }

      let plaintext = try AES.CFB.decrypt(
        Array(buffer: message),
        using: symmetricKey,
        nonce: .init(data: nonce)
      )
      guard plaintext.count == message.readableBytes else {
        throw CodingError.failedToParseDataSize
      }
      message.clear()
      message.writeBytes(plaintext)

      padding = nextPadding()

      guard let frameLength = try parseLength(from: &message) else {
        // There, we have already got enough bytes to parse frame length but still failed, so we
        // need throw error.
        throw CodingError.failedToParseDataSize
      }

      // We don't actual read the payload length data while parsing, so there the full frame
      // length should contain payload length data size.
      return (frameLength + payloadLengthDataSize, padding)
    case .aes128Gcm, .chaCha20Poly1305:
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
        guard let frameLength = try parseLength(from: &frameLengthData) else {
          // We have already checked that data is enough to read frame length,
          // so there we should throw error instead of return nil.
          throw CodingError.failedToParseDataSize
        }
        return (frameLength, padding)
      }

      var symmetricKey = KDF.deriveKey(
        inputKeyMaterial: .init(data: symmetricKey),
        info: Array("auth_len".utf8)
      )
      let nonce = withUnsafeBytes(of: nonceLeading.bigEndian) {
        Array($0) + Array(self.nonce.prefix(12).suffix(10))
      }

      if contentSecurity == .aes128Gcm {
        let sealedBox = try AES.GCM.SealedBox(combined: nonce + Array(buffer: frameLengthData))
        let frameLengthData = try AES.GCM.open(sealedBox, using: symmetricKey)
        let frameLength = frameLengthData.withUnsafeBytes {
          $0.load(as: UInt16.self).bigEndian + UInt16(tagDataLength)
        }
        return (Int(frameLength), padding)
      } else {
        symmetricKey = generateChaChaPolySymmetricKey(inputKeyMaterial: symmetricKey)
        let sealedBox = try ChaChaPoly.SealedBox(combined: nonce + Array(buffer: frameLengthData))
        let frameLengthData = try ChaChaPoly.open(sealedBox, using: symmetricKey)
        let frameLength = frameLengthData.withUnsafeBytes {
          $0.load(as: UInt16.self).bigEndian + UInt16(tagDataLength)
        }
        return (Int(frameLength), padding)
      }
    default:
      throw CodingError.operationUnsupported
    }
  }

  private func parseLength(from buffer: inout ByteBuffer) throws -> Int? {
    guard let l = buffer.readInteger(as: UInt16.self) else {
      return nil
    }

    guard options.contains(.chunkMasking) else {
      return Int(l)
    }

    let frameLength = hasher.read(digestSize: 2).withUnsafeBytes {
      let mask = $0.load(as: UInt16.self).bigEndian
      return mask ^ l
    }
    return Int(frameLength)
  }

  /// Parse frame from buffer with specified frameLength and padding..
  private func parseFrame(from buffer: inout ByteBuffer, frameLength: Int, padding: Int) throws
    -> ByteBuffer?
  {
    guard var message = buffer.readSlice(length: frameLength) else {
      return nil
    }
    switch contentSecurity {
    case .none:
      guard options.contains(.chunkStream) else {
        return message
      }

      guard commandCode == .udp else {
        // Transfer type stream...
        return message
      }
      // TODO: Parse UDP Frame
      return nil
    case .aes128Cfb:
      guard options.contains(.chunkStream) else {
        return message
      }

      // AES-CFB-128 decrypt...
      let plaintext = try AES.CFB.decrypt(
        Array(buffer: message),
        using: symmetricKey,
        nonce: .init(data: nonce)
      )

      message.clear()
      message.writeBytes(plaintext)

      // Those 2(`MemoryLayout<UInt16>.size`) bytes contain payload data length data,
      // we should move reader index forward to ignore those bytes.
      message.moveReaderIndex(forwardBy: MemoryLayout<UInt16>.size)
      guard let code = message.readInteger(as: UInt32.self) else {
        throw CodingError.failedToParseData
      }
      let authenticationFailure = message.withUnsafeReadableBytes { buffPtr in
        FNV1a32.hash(data: buffPtr) != code
      }
      guard !authenticationFailure else {
        throw CryptoKitError.authenticationFailure
      }
      return message
    case .aes128Gcm, .chaCha20Poly1305:
      // Tag for AES-GCM or ChaCha20-Poly1305 are both 16.
      let nonce = withUnsafeBytes(of: nonceLeading.bigEndian) {
        Array($0) + Array(self.nonce.prefix(12).suffix(10))
      }

      // Remove random padding bytes.
      let combined = nonce + Array(buffer: message).dropLast(padding)

      message.clear()
      if contentSecurity == .aes128Gcm {
        let frame = try AES.GCM.open(.init(combined: combined), using: .init(data: symmetricKey))
        message.writeBytes(frame)
      } else {
        let symmetricKey = generateChaChaPolySymmetricKey(inputKeyMaterial: symmetricKey)
        let frame = try ChaChaPoly.open(.init(combined: combined), using: symmetricKey)
        message.writeBytes(frame)
      }

      nonceLeading &+= 1
      return message
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
  ///   - contentSecurity: The security type use to control message decoding method.
  ///   - symmetricKey: SymmetricKey for decriptor.
  ///   - nonce: Nonce for decryptor.
  ///   - options: The stream options use to control data padding and mask.
  ///   - headDecryptionStrategy: Strategy to decrypt encrypted response head. Defaults to `.useAEAD`.
  public init(
    contentSecurity: ContentSecurity,
    symmetricKey: SymmetricKey,
    nonce: [UInt8],
    options: StreamOptions,
    commandCode: CommandCode,
    headDecryptionStrategy: ResponseHeadDecryptionStrategy = .useAEAD
  ) {
    if Out.self == VMESSPart<VMESSResponseHead, ByteBuffer>.self {
      self.kind = .response
    } else {
      preconditionFailure("unsupported VMESS message type \(Out.self)")
    }
    self.parser = BetterVMESSParser(
      kind: kind,
      contentSecurity: contentSecurity,
      symmetricKey: symmetricKey,
      nonce: nonce,
      options: options,
      commandCode: commandCode,
      headDecryptionStrategy: headDecryptionStrategy
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
