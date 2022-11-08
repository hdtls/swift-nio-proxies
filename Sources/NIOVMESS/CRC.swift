//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2022 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

/// CRC 32 IEEE checksum.
enum CRC32 {

    @usableFromInline
    static let table: [UInt32] = {
        (0...255).map { i -> UInt32 in
            (0..<8).reduce(
                UInt32(i),
                { c, _ in
                    (c % 2 == 0) ? (c >> 1) : (0xEDB8_8320 ^ (c >> 1))
                }
            )
        }
    }()

    @inlinable
    static func checksum<Bytes: Sequence>(_ data: Bytes) -> UInt32 where Bytes.Element == UInt8 {
        ~(data.reduce(~UInt32(0)) { crc, byte in
            (crc >> 8) ^ table[(Int(crc) ^ Int(byte)) & 0xFF]
        })
    }
}
