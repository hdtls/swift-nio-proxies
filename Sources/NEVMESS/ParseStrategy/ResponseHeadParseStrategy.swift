//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2023 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

@preconcurrency import Crypto
import Foundation
import NIOCore

public enum ResponseHeadDecryptionStrategy: Sendable {
  case useAEAD
  case useLegacy
}

// +----------+-----+----------+---------+----------+------+
// | RES.AUTH | OPT | CMD.CODE | CMD.LEN |    CMD   | DATA |
// +----------+-----+----------+---------+----------+------+
// |     1    |  1  |     1    |    1    | VARIABLE |  N   |
// +----------+-----+----------+---------+----------+------+

/// Response head part parse strategy.
struct ResponseHeadParseStrategy: Sendable {

  typealias ParseInput = ByteBuffer

  /// The type of the data type.
  typealias ParseOutput = (VMESSResponseHead, Int)?

  let symmetricKey: SymmetricKey

  let nonce: [UInt8]

  let decryptionStrategy: ResponseHeadDecryptionStrategy

  func parse(_ value: ParseInput) throws -> ParseOutput {
    // Make it mutable.
    var headPartData = value
    var consumed = 0

    if case .useAEAD = decryptionStrategy {
      // 2 byte packet length data and 16 overhead
      let tagByteCount = 16
      var bytesToCopy = 18
      guard var combined = headPartData.readBytes(length: bytesToCopy) else {
        return nil
      }

      let material1 = symmetricKey
      let material2 = SymmetricKey(data: nonce)

      var extraKDFInfoMsg = Array("AEAD Resp Header Len Key".utf8)
      var symmetricKey = KDF.deriveKey(inputKeyMaterial: material1, info: extraKDFInfoMsg)
      extraKDFInfoMsg = Array("AEAD Resp Header Len IV".utf8)
      let ciphertextLengthData = try KDF.deriveKey(
        inputKeyMaterial: material2,
        info: extraKDFInfoMsg
      ).withUnsafeBytes {
        combined = Array($0.prefix(12)) + combined
        return try AES.GCM.open(.init(combined: combined), using: symmetricKey)
      }
      assert(ciphertextLengthData.count == MemoryLayout<UInt16>.size)
      let ciphertextLength = ciphertextLengthData.withUnsafeBytes {
        $0.load(as: UInt16.self).bigEndian
      }

      bytesToCopy = Int(ciphertextLength) + tagByteCount
      guard let ciphertextAndTag = headPartData.readBytes(length: bytesToCopy) else {
        // return nil to tell decoder we need more data.
        return nil
      }

      extraKDFInfoMsg = Array("AEAD Resp Header Key".utf8)
      symmetricKey = KDF.deriveKey(inputKeyMaterial: material1, info: extraKDFInfoMsg)
      extraKDFInfoMsg = Array("AEAD Resp Header IV".utf8)
      let plaintext = try KDF.deriveKey(
        inputKeyMaterial: material2,
        info: extraKDFInfoMsg
      ).withUnsafeBytes {
        combined = Array($0.prefix(12)) + ciphertextAndTag
        return try AES.GCM.open(.init(combined: combined), using: symmetricKey)
      }

      consumed = headPartData.readerIndex - value.readerIndex
      headPartData.clear()
      headPartData.writeBytes(plaintext)
    }

    guard let (head, dataReaded) = try _parse(headPartData) else {
      return nil
    }
    return (head, dataReaded + consumed)
  }

  /// Should be private but for tests we make it internal.
  func _parse(_ value: ParseInput) throws -> ParseOutput {
    var headPartData = value
    guard let authenticationCode = headPartData.readInteger(as: UInt8.self) else {
      if case .useAEAD = decryptionStrategy {
        throw CodingError.failedToParseData
      } else {
        return nil
      }
    }

    guard let rawValue = headPartData.readInteger(as: UInt8.self) else {
      if case .useAEAD = decryptionStrategy {
        throw CodingError.failedToParseData
      } else {
        return nil
      }
    }
    let options = StreamOptions.init(rawValue: rawValue)

    guard let code: UInt8 = headPartData.readInteger() else {
      if case .useAEAD = decryptionStrategy {
        throw CodingError.failedToParseData
      } else {
        return nil
      }
    }

    var head = VMESSResponseHead.init(
      authenticationCode: authenticationCode,
      options: options,
      instructionCode: .init(rawValue: code),
      instruction: nil
    )

    guard let instructionDataLength = headPartData.readInteger(as: UInt8.self) else {
      if case .useAEAD = decryptionStrategy {
        throw CodingError.failedToParseData
      } else {
        return nil
      }
    }

    guard instructionDataLength > 0 else {
      let consumed =
        decryptionStrategy == .useAEAD ? 0 : headPartData.readerIndex - value.readerIndex
      return (head, consumed)
    }

    // This read should always success, adding Nil-Coalescing Operator is to avoid force unwrapping.
    guard let slice = headPartData.readSlice(length: Int(instructionDataLength)) else {
      throw CodingError.failedToParseData
    }

    head.instruction = try ResponseInstructionParseStrategy(instructionCode: code).parse(slice)

    let consumed =
      decryptionStrategy == .useAEAD ? 0 : headPartData.readerIndex - value.readerIndex
    return (head, consumed)
  }
}
