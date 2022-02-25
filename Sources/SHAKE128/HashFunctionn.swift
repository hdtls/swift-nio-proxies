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

#if !canImport(Crypto)
import Foundation

public protocol HashFunction {
    
    /// The block size of the hash function. It is different from the output size that can be retrieved from Digest.byteCount.
    static var blockByteCount: Int { get }
    
    associatedtype Digest: Digest
    
    /// Initializes the hasher instance.
    init()
    
    /// Updates the hasher with the buffer.
    ///
    /// - Parameter bufferPointer: The buffer to update the hash
    mutating func update(bufferPointer: UnsafeRawBufferPointer)
    
    /// Returns the digest from the input in the hash function instance.
    ///
    /// - Returns: The digest of the data
    func finalize() -> Self.Digest
}

extension HashFunction {
    /// Computes a digest of the buffer.
    ///
    /// - Parameter bufferPointer: The buffer to be hashed
    /// - Returns: The computed digest
    @inlinable
    static func hash(bufferPointer: UnsafeRawBufferPointer) -> Digest {
        var hasher = Self()
        hasher.update(bufferPointer: bufferPointer)
        return hasher.finalize()
    }
    
    /// Computes a digest of the data.
    ///
    /// - Parameter data: The data to be hashed
    /// - Returns: The computed digest
    @inlinable
    public static func hash<D: DataProtocol>(data: D) -> Self.Digest {
        var hasher = Self()
        hasher.update(data: data)
        return hasher.finalize()
    }
    
    /// Updates the hasher with the data.
    ///
    /// - Parameter data: The data to update the hash
    @inlinable
    public mutating func update<D: DataProtocol>(data: D) {
        data.regions.forEach { (regionData) in
            regionData.withUnsafeBytes({ (dataPtr) in
                self.update(bufferPointer: dataPtr)
            })
        }
    }
}
#endif
