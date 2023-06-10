//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2023 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

@_exported import Crypto
import Foundation

#if canImport(CommonCrypto)
private typealias AESECBImpl = CommonCryptoAESECBImpl
#else
private typealias AESECBImpl = OpenSSLAESECBImpl
#endif

extension AES {

  /// AES in ECB mode with 128-bit key.
  public enum ECB {

    public typealias SealedBox = Data

    /// Encrypts data using AES-128-ECB with PKCS7Padding.
    ///
    /// - Parameters:
    ///   - message: The message to encrypt
    ///   - key: An encryption key of 128 bits
    /// - Returns: A sealed box returning the ciphertext
    public static func seal<Plaintext: DataProtocol>(
      _ message: Plaintext,
      using key: SymmetricKey
    ) throws -> SealedBox {
      try AESECBImpl.seal(message, using: key)
    }

    /// Decrypts data using AES-128-ECB with PKCS7Padding.
    ///
    /// - Parameters:
    ///   - sealedBox: The sealed box to decrypt
    ///   - key: An encryption key of 128 bits
    /// - Returns: The message if opening was successful
    public static func open(_ sealedBox: SealedBox, using key: SymmetricKey) throws -> Data {
      try AESECBImpl.open(sealedBox, using: key)
    }
  }
}
