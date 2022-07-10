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

private protocol Updatable {

    static var blockSize: Int { get }

    mutating func update(bufferPointer: UnsafeRawBufferPointer)

    mutating func update<D: DataProtocol>(data: D)

    func get() -> [UInt8]
}

extension SHA256: Updatable {

    static var blockSize: Int {
        64
    }

    func get() -> [UInt8] {
        finalize().withUnsafeBytes { ptr in
            Array(ptr)
        }
    }
}

struct KDF {

    private struct __HMAC: Updatable {

        static var blockSize: Int { 64 }

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

            if key.withUnsafeBytes({ $0.count }) == U.blockSize {
                K = key
            } else if key.withUnsafeBytes({ $0.count }) > U.blockSize {
                K = key.withUnsafeBytes { (keyBytes) in
                    var hash = H()
                    hash.update(bufferPointer: keyBytes)
                    return hash.get()
                }
            } else {
                var keyArray = Array(repeating: UInt8(0), count: U.blockSize)
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
    static func deriveKey<Info>(
        inputKeyMaterial: SymmetricKey,
        info: [Info],
        outputByteCount: Int? = nil
    ) -> SymmetricKey where Info: DataProtocol {
        var updatable = __HMAC(H: { SHA256() }, key: .init(data: KDFSaltConstVMessAEADKDF))

        for path in info {
            updatable = __HMAC(H: { updatable }, key: .init(data: Array(path)))
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

struct KDF12 {

    /// Derives a 12 byte symmetric key using the KDF algorithm.
    ///
    /// - Parameters:
    ///   - inputKeyMaterial: Input key material.
    ///   - paths: path list.
    ///   - outputByteCount: The desired number of output bytes, if nill output all bytes, default is nil.
    /// - Returns: The derived key
    static func deriveKey<Info>(inputKeyMaterial: SymmetricKey, info: [Info]) -> SymmetricKey
    where Info: DataProtocol {
        KDF.deriveKey(inputKeyMaterial: inputKeyMaterial, info: info, outputByteCount: 12)
    }
}

struct KDF16 {
    /// Derives a 16 byte symmetric key using the KDF algorithm.
    ///
    /// - Parameters:
    ///   - inputKeyMaterial: Input key material.
    ///   - paths: path list.
    ///   - outputByteCount: The desired number of output bytes, if nill output all bytes, default is nil.
    /// - Returns: The derived key
    static func deriveKey<Info>(inputKeyMaterial: SymmetricKey, info: [Info]) -> SymmetricKey
    where Info: DataProtocol {
        KDF.deriveKey(inputKeyMaterial: inputKeyMaterial, info: info, outputByteCount: 16)
    }
}

func generateCmdKey(_ id: UUID) -> SymmetricKey {
    withUnsafeBytes(of: id) {
        var hasher = Insecure.MD5.init()
        hasher.update(bufferPointer: $0)
        hasher.update(data: "c48619fe-8f02-49e0-b9e9-edf763e17e21".data(using: .utf8)!)
        return .init(data: hasher.finalize())
    }
}

func generateChaChaPolySymmetricKey<Key>(inputKeyMaterial: Key) -> SymmetricKey
where Key: DataProtocol {
    var md5 = Insecure.MD5()
    md5.update(data: inputKeyMaterial)
    return md5.finalize().withUnsafeBytes { ptr in
        var hasher = Insecure.MD5()
        hasher.update(bufferPointer: ptr)
        return hasher.finalize().withUnsafeBytes {
            return .init(data: Array(ptr) + Array($0))
        }
    }
}
