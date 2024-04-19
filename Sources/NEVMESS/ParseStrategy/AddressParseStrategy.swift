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

import NIOCore

// +----------+----------+------+
// | ADDR.LEN |   ADDR   | PORT |
// +----------+----------+------+
// |     1    | VARIABLE |   2  |
// +----------+----------+------+

/// Parse address with specified data.
struct AddressParseStrategy: Sendable {

  typealias ParseInput = ByteBuffer

  typealias ParseOutput = (address: String?, port: Int)

  func parse(_ value: ParseInput) throws -> ParseOutput {
    var startIndex = value.readerIndex
    guard let l = value.getInteger(at: startIndex, as: UInt8.self) else {
      throw CodingError.failedToParseData
    }

    startIndex += 1
    var address: String?
    if l > 0 {
      address = value.getString(at: startIndex, length: Int(l))
      guard address != nil else {
        throw CodingError.failedToParseData
      }
    }

    startIndex += Int(l)
    guard let port = value.getInteger(at: startIndex, as: UInt16.self) else {
      throw CodingError.failedToParseData
    }

    return (address, Int(port))
  }
}
