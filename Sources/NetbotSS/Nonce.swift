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

import Foundation

extension Array where Element == UInt8 {
    
    /// Increment array like `sodium_increment(_:)`
    /// - Returns: result value
    mutating func increment(_ length: Int) {
        var c: UInt8 = 1
        self = map { e in
            c += e
            defer { c >>= 8 }
            return c & 0xFF
        }
    }
}
