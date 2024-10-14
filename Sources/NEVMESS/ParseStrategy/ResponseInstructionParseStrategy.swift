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

import Foundation
import NIOCore

/// Response head part instruction parse strategy.
struct ResponseInstructionParseStrategy: Sendable {

  typealias ParseInput = ByteBuffer

  /// The type of the data type.
  typealias ParseOutput = ResponseInstruction

  let instructionCode: UInt8

  func parse(_ value: ParseInput) throws -> ParseOutput {
    var byteBuffer = value

    guard let expectedCode = byteBuffer.readInteger(as: UInt32.self) else {
      throw CodingError.failedToParseData
    }

    try byteBuffer.withUnsafeReadableBytes {
      let code = FNV1a32.hash(data: $0)
      guard code == expectedCode else {
        throw VMESSError.authenticationFailure
      }
    }

    switch instructionCode {
    case 1:
      let parseInput = byteBuffer.slice()
      let dynamicPortInstruction = try DynamicPortInstructionParseStrategy().parse(parseInput)
      return dynamicPortInstruction
    default:
      throw CodingError.operationUnsupported
    }
  }
}

// +----------+----------+------+------+----------------+-------+-------+
// | ADDR.LEN |   ADDR   | PORT | UUID | ALTER ID COUNT | LEVEL | VALID |
// +----------+----------+------+------+----------------+-------+-------+
// |     1    | VARIABLE |   2  |  16  |        2       |   1   |   1   |
// +----------+----------+------+------+----------------+-------+-------+
//
struct DynamicPortInstructionParseStrategy: Sendable {

  typealias ParseInput = ByteBuffer

  typealias ParseOutput = DynamicPortInstruction

  func parse(_ value: ParseInput) throws -> ParseOutput {
    var byteBuffer = value

    guard let l = byteBuffer.getInteger(at: byteBuffer.readerIndex, as: UInt8.self) else {
      throw CodingError.failedToParseData
    }
    let addressLength = Int(l)

    let bytesToCopy = 3 + addressLength
    guard let slice = byteBuffer.readSlice(length: bytesToCopy) else {
      throw CodingError.failedToParseData
    }
    let (address, port) = try AddressParseStrategy().parse(slice)

    guard let uuid = byteBuffer.readBytes(length: MemoryLayout<UUID>.size) else {
      throw CodingError.failedToParseData
    }
    let uid = uuid.withUnsafeBytes {
      $0.load(as: UUID.self)
    }

    guard let numberOfAlterIDs = byteBuffer.readInteger(as: UInt16.self),
      let level = byteBuffer.readInteger(as: UInt8.self),
      let effectiveTime = byteBuffer.readInteger(as: UInt8.self)
    else {
      throw CodingError.failedToParseData
    }

    return DynamicPortInstruction(
      address: address,
      port: port,
      uid: uid,
      level: UInt32(level),
      numberOfAlterIDs: numberOfAlterIDs,
      effectiveTime: effectiveTime
    )
  }
}
