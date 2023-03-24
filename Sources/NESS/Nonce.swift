//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2021 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

extension Array where Element == UInt8 {

  /// Increment array like `sodium_increment(_:)`
  /// - Returns: result value
  mutating func increment(_ length: Int) {
    var c: UInt16 = 1

    self = self.map { e in
      c += UInt16(e)
      defer { c >>= 8 }
      return UInt8(truncatingIfNeeded: c)
    }
  }
}
