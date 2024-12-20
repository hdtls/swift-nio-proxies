//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2021 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
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
private func bytesToKey(_ secretKey: String, saltByteCount: Int, outputByteCount: Int) -> [UInt8] {
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

/// This function that takes a secret key, a non-secret salt, an info string, and produces a subkey that is
/// cryptographically strong even if the input secret key is weak.
func hkdfDerivedSymmetricKey<Salt: DataProtocol>(
  secretKey: String,
  salt: Salt,
  outputByteCount: Int
) -> SymmetricKey {
  let inputKeyMaterial = SymmetricKey(
    data: bytesToKey(secretKey, saltByteCount: salt.count, outputByteCount: outputByteCount)
  )
  /// The info string binds the generated subkey to a specific application context. In our case, it must be the string
  /// "ss-subkey" without quotes.
  let info = Data("ss-subkey".utf8)

  #if canImport(Darwin)
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
