//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright © 2019 Netbot Ltd. and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import CNIOSodium

extension UInt16 {
    var uint8: [UInt8] {
        return [UInt8(self >> 8 & 0x00ff), UInt8(self & 0x00ff)]
    }
}

extension Array {
    var slice: ArraySlice<Element> {
        return self[self.startIndex ..< self.endIndex]
    }
}

extension Array where Element: FixedWidthInteger {
    static func random(_ count: Int) -> [Element] {
        var buf: [Element] = allocate(count)
        arc4random_buf(&buf, count)
        return buf
    }
}

func allocate<T: FixedWidthInteger>(_ cnt: Int) -> [T] {
    return [T](repeating: 0, count: cnt)
}

func unique(_ buf: inout [UInt8], _ size: Int) {
    sodium_increment(&buf, size)
}
