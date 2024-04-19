//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2024 Junfeng Zhang and the Netbot project authors
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

@testable import NESS

extension Data {

  /// Read `NetAddress` from buffer.
  /// - Returns: If success return `NetAddress` else return nil for need more bytes.
  mutating func readAddress() throws -> NWEndpoint? {
    let data = self
    var byteBuffer = ByteBuffer(bytes: data)
    defer {
      self = Data(Array(buffer: byteBuffer))
    }
    return try byteBuffer.readRFC1928RequestAddressAsEndpoint()
  }

  /// Write `NetAddress` to `ByteBuffer`.
  /// - Parameter address: The address waiting to write.
  /// - Returns: Byte count.
  @discardableResult
  mutating func writeAddress(_ address: NWEndpoint) -> Int {
    var byteBuffer = ByteBuffer()
    defer {
      append(contentsOf: Array(buffer: byteBuffer))
    }
    return byteBuffer.writeEndpointInRFC1928RequestAddressFormat(address)
  }
}
