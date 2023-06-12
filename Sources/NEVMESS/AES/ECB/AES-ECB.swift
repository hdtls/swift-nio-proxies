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

    /// Encrypts data using AES-128-ECB with PKCS7Padding.
    ///
    /// - Parameters:
    ///   - message: The message to encrypt
    ///   - key: A 128-bits encryption key
    /// - Returns: The encrypted ciphertext
    public static func encrypt<Plaintext>(
      _ message: Plaintext,
      using key: SymmetricKey
    ) throws -> Data where Plaintext: DataProtocol {
      try AESECBImpl.encrypt(message, using: key)
    }

    /// Decrypts data using AES-128-ECB with PKCS7Padding.
    ///
    /// - Parameters:
    ///   - message: The message to decrypt
    ///   - key: A 128-bits encryption key
    /// - Returns: The decrypted message if success
    public static func decrypt<Ciphertext>(
      _ message: Ciphertext,
      using key: SymmetricKey
    ) throws -> Data where Ciphertext: DataProtocol {
      try AESECBImpl.decrypt(message, using: key)
    }
  }
}
