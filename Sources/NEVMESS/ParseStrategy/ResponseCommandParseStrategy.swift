//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2023 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation
import NIOCore

/// Response head part command parse strategy.
struct ResponseCommandParseStrategy: Sendable {

  typealias ParseInput = ByteBuffer

  /// The type of the data type.
  typealias ParseOutput = ResponseCommand

  let commandCode: UInt8

  func parse(_ value: ParseInput) throws -> ParseOutput {
    var commandData = value

    guard let expectedCode = commandData.readInteger(as: UInt32.self) else {
      throw CodingError.failedToParseData
    }

    try commandData.withUnsafeReadableBytes {
      let code = FNV1a32.hash(data: $0)
      guard code == expectedCode else {
        throw VMESSError.authenticationFailure
      }
    }

    switch commandCode {
    case 1:
      let command = try DynamicPortInstructionParseStrategy().parse(commandData.slice())
      return command
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
    var commandData = value

    guard let l = commandData.getInteger(at: commandData.readerIndex, as: UInt8.self) else {
      throw CodingError.failedToParseData
    }
    let addressLength = Int(l)

    let bytesToCopy = 3 + addressLength
    guard let slice = commandData.readSlice(length: bytesToCopy) else {
      throw CodingError.failedToParseData
    }
    let (address, port) = try AddressParseStrategy().parse(slice)

    guard let uuid = commandData.readBytes(length: MemoryLayout<UUID>.size) else {
      throw CodingError.failedToParseData
    }
    let uid = uuid.withUnsafeBytes {
      $0.load(as: UUID.self)
    }

    guard let numberOfAlterIDs = commandData.readInteger(as: UInt16.self),
      let level = commandData.readInteger(as: UInt8.self),
      let effectiveTime = commandData.readInteger(as: UInt8.self)
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
