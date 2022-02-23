//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2021 Junfeng Zhang. and the Netbot project authors
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

/// Swift version FNV-1a for 32 bits.
func openSSL_hash32<Bytes: Sequence>(_ data: Bytes) -> UInt32 where Bytes.Element == UInt8 {
    // These are the FNV-1a parameters for 32 bits.
    let prime: UInt32 = 16777619
    let initialResult: UInt32 = 2166136261
    
    return data.reduce(initialResult) { partialResult, byte in
        var partialResult = partialResult
        partialResult ^= UInt32(byte)
        partialResult &*= prime
        return partialResult
    }
}

func openSSL_hash32(_ ptr: UnsafeRawBufferPointer) -> UInt32 {
    openSSL_hash32(Array(ptr))
}
