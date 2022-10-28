//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2021 Junfeng Zhang and the Netbot project authors
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

/// Generate key like `Evp_BytesToKey`.
/// - Parameters:
///   - secretKey: user input secretKey
///   - outputByteCount: key length for deliver key.
///   - saltByteCount: salt length for deliver key.
/// - Returns: hash result
@inline(__always)
private func __bytesToKey(_ secretKey: String, saltByteCount: Int, outputByteCount: Int) -> [UInt8]
{
    var i = 0
    var initialResult: [UInt8] = []
    var partialResult: [UInt8] = []
    while initialResult.count < outputByteCount + saltByteCount {
        var bytes = Array(secretKey.utf8)
        if i > 0 {
            bytes = partialResult + bytes
        }
        partialResult = Array(Insecure.MD5.hash(data: bytes))
        initialResult.append(contentsOf: partialResult)
        i += 1
    }
    return Array(initialResult.prefix(outputByteCount))
}

///
/// Key Derivation
///
/// HKDF_SHA1 is a function that takes a secret key, a non-secret salt, an info string, and produces a subkey that is
/// cryptographically strong even if the input secret key is weak.
///
///      HKDF_SHA1(key, salt, info) => subkey
///
/// The info string binds the generated subkey to a specific application context. In our case, it must be the string
/// "ss-subkey" without quotes.
///
/// We derive a per-session subkey from a pre-shared master key using HKDF_SHA1. Salt must be unique through the entire
/// life of the pre-shared master key.
///
func hkdfDerivedSymmetricKey<Salt: DataProtocol>(
    secretKey: String,
    salt: Salt,
    outputByteCount: Int
) -> SymmetricKey {
    let inputKeyMaterial = SymmetricKey(
        data: __bytesToKey(secretKey, saltByteCount: salt.count, outputByteCount: outputByteCount)
    )
    let info = "ss-subkey".data(using: .utf8)!

    #if (os(macOS) || os(iOS) || os(watchOS) || os(tvOS))
    if #available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *) {
        return HKDF<Insecure.SHA1>.deriveKey(
            inputKeyMaterial: inputKeyMaterial,
            salt: salt,
            info: info,
            outputByteCount: outputByteCount
        )
    } else {
        // TODO: Fallback on earlier versions
        assertionFailure("TODO: Fallback on earlier version")
        return .init(size: .bits256)
    }
    #else
    return HKDF<Insecure.SHA1>.deriveKey(
        inputKeyMaterial: inputKeyMaterial,
        salt: salt,
        info: info,
        outputByteCount: outputByteCount
    )
    #endif
}
