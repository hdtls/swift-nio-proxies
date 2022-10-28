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

@_implementationOnly import CSHAKE128
import Foundation

public struct SHAKE128: HashFunctionImplementationDetails {

    public typealias Digest = SHAKE128Digest

    public static var blockByteCount: Int {
        return 168
    }

    public static var byteCount: Int {
        return 16
    }

    var impl: OpenSSLDigestImpl<SHAKE128>

    /// Initializes the hash function instance.
    public init() {
        impl = OpenSSLDigestImpl()
    }

    // Once https://github.com/apple/swift-evolution/pull/910 is landed,
    // we will be able to implement `init` here and remove the duplicate code.

    public mutating func update(bufferPointer: UnsafeRawBufferPointer) {
        impl.update(data: bufferPointer)
    }

    public func read(digestSize: Int) -> Self.Digest {
        return impl.read(digestSize: digestSize)
    }

    /// Returns the digest from the data input in the hash function instance.
    ///
    /// - Returns: The digest of the inputted data
    public func finalize() -> Self.Digest {
        return impl.finalize()
    }
}
