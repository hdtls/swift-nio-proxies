//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2022 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto

protocol DigestPrivate: Digest {
  init?(bufferPointer: UnsafeRawBufferPointer)
}

extension DigestPrivate {
  @inlinable
  init?(bytes: [UInt8]) {
    let some = bytes.withUnsafeBytes { bufferPointer in
      return Self(bufferPointer: bufferPointer)
    }

    if some != nil {
      self = some!
    } else {
      return nil
    }
  }
}
