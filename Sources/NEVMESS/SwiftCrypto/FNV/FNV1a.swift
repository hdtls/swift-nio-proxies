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

enum FNV1a32 {

  /// FNV-1a 32 bit variant hash.
  ///
  /// See [Fowler–Noll–Vo hash function](https://en.wikipedia.org/wiki/Fowler–Noll–Vo_hash_function) for more details.
  ///
  /// - Parameter data: Data to combined.
  /// - Returns: Hash value.
  @inlinable static func hash<D>(data: D) -> UInt32 where D: DataProtocol {
    let prime: UInt32 = 16_777_619
    let offsetBasis: UInt32 = 2_166_136_261

    return data.reduce(offsetBasis) { partialResult, byte in
      var partialResult = partialResult
      partialResult ^= UInt32(byte)
      partialResult &*= prime
      return partialResult
    }
  }
}
