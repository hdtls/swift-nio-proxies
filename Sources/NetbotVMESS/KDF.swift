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

import Crypto
import Foundation

fileprivate protocol Updatable {
    
    static var blockByteCount: Int { get }
    
    mutating func update(bufferPointer: UnsafeRawBufferPointer)
    
    mutating func update<D: DataProtocol>(data: D)
    
    func get() -> [UInt8]
}

extension SHA256: Updatable {
    
    fileprivate func get() -> [UInt8] {
        finalize().withUnsafeBytes { ptr in
            Array(ptr)
        }
    }
}

struct KDF {
    
    private struct __HMAC: Updatable {
        
        static var blockByteCount: Int { SHA256.blockByteCount }
        
        mutating func update(bufferPointer: UnsafeRawBufferPointer) {
            innerHasher.update(bufferPointer: bufferPointer)
        }
        
        mutating func update<D: DataProtocol>(data: D) {
            data.regions.forEach { (regionData) in
                regionData.withUnsafeBytes({ (dataPtr) in
                    self.update(bufferPointer: dataPtr)
                })
            }
        }
        
        func get() -> [UInt8] {
            let buffer = innerHasher.get()
            var outerHashForFinalization = outerHasher
            buffer.withUnsafeBytes {
                outerHashForFinalization.update(bufferPointer: $0)
            }
            return outerHashForFinalization.get()
        }
        
        var outerHasher: Updatable
        var innerHasher: Updatable
        
        init<U: Updatable>(H: () -> U, key: SymmetricKey) {
            var K: ContiguousBytes
            
            if key.withUnsafeBytes({ $0.count }) == U.blockByteCount {
                K = key
            } else if key.withUnsafeBytes({ $0.count }) > U.blockByteCount {
                K = key.withUnsafeBytes { (keyBytes)  in
                    var hash = H()
                    hash.update(bufferPointer: keyBytes)
                    return hash.get()
                }
            } else {
                var keyArray = Array(repeating: UInt8(0), count: U.blockByteCount)
                key.withUnsafeBytes { keyArray.replaceSubrange(0..<$0.count, with: $0) }
                K = keyArray
            }
            
            self.innerHasher = H()
            let innerKey = K.withUnsafeBytes {
                return $0.map({ (keyByte) in
                    keyByte ^ 0x36
                })
            }
            innerHasher.update(data: innerKey)
            
            self.outerHasher = H()
            let outerKey = K.withUnsafeBytes {
                return $0.map({ (keyByte) in
                    keyByte ^ 0x5c
                })
            }
            outerHasher.update(data: outerKey)
        }
    }
    
    /// Derives a symmetric key using the KDF algorithm.
    ///
    /// - Parameters:
    ///   - inputKeyMaterial: Input key material.
    ///   - paths: path list.
    ///   - outputByteCount: The desired number of output bytes, if nill output all bytes, default is nil.
    /// - Returns: The derived key
    static func deriveKey<INFO: Sequence>(inputKeyMaterial: SymmetricKey, info: INFO..., outputByteCount: Int? = nil) -> SymmetricKey where INFO.Element == UInt8 {
        var updatable: __HMAC = __HMAC.init(H: { SHA256() }, key: .init(data: KDFSaltConstVMessAEADKDF))
        for path in info {
            updatable = __HMAC.init(H: {
                updatable
            }, key: .init(data: Array(path)))
        }
        
        inputKeyMaterial.withUnsafeBytes {
            updatable.update(bufferPointer: $0)
        }
        
        guard let maxLength = outputByteCount else {
            return .init(data: updatable.get())
        }
        return .init(data: updatable.get().prefix(maxLength))
    }
}
