//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2022 Junfeng Zhang. and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation

public struct SHAKE128Digest: DigestPrivate {
    let bytes: (UInt64, UInt64)
    
    init?(bufferPointer: UnsafeRawBufferPointer) {
        guard bufferPointer.count == 16 else {
            return nil
        }
        
        var bytes = (UInt64(0), UInt64(0))
        withUnsafeMutableBytes(of: &bytes) { targetPtr in
            targetPtr.copyMemory(from: bufferPointer)
        }
        self.bytes = bytes
    }
    
    public static var byteCount: Int {
        return 16
    }
    
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try Swift.withUnsafeBytes(of: bytes) {
            let boundsCheckedPtr = UnsafeRawBufferPointer(start: $0.baseAddress,
                                                          count: Self.byteCount)
            return try body(boundsCheckedPtr)
        }
    }
    
    private func toArray() -> ArraySlice<UInt8> {
        var array = [UInt8]()
        array.appendByte(bytes.0)
        array.appendByte(bytes.1)
        return array.prefix(upTo: Self.byteCount)
    }
    
    public var description: String {
        return "\("SHAKE128") digest: \(toArray().hexString)"
    }
    
    public func hash(into hasher: inout Hasher) {
        self.withUnsafeBytes { hasher.combine(bytes: $0) }
    }
}
