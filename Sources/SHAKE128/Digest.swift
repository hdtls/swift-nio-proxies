//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
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

#if canImport(Crypto)
@_exported import Crypto
#endif

#if !canImport(Crypto)
/// A protocol defining requirements for digests
public protocol Digest: Hashable, ContiguousBytes, CustomStringConvertible, Sequence
where Element == UInt8 {
    static var byteCount: Int { get }
}
#endif

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

extension Digest {
    public func makeIterator() -> Array<UInt8>.Iterator {
        self.withUnsafeBytes({ (buffPtr) in
            return Array(buffPtr).makeIterator()
        })
    }
}

// We want to implement constant-time comparison for digests.
extension Digest {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        return openSSLSafeCompare(lhs, rhs)
    }

    public static func == <D: DataProtocol>(lhs: Self, rhs: D) -> Bool {
        if rhs.regions.count != 1 {
            let rhsContiguous = Data(rhs)
            return openSSLSafeCompare(lhs, rhsContiguous)
        } else {
            return openSSLSafeCompare(lhs, rhs.regions.first!)
        }
    }

    public var description: String {
        return "\(Self.self): \(Array(self).hexString)"
    }
}
