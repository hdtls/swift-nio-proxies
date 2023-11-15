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
private typealias AESCFBImpl = CommonCryptoAESCFBImpl
#else
private typealias AESCFBImpl = OpenSSLAESCFBImpl
#endif

extension AES {

  /// AES in CFB mode with 128-bit key.
  public enum CFB {

    public struct Nonce: ContiguousBytes, Sequence {

      let bytes: Data

      private static let byteCount = 16

      public typealias Iterator = IndexingIterator<[UInt8]>

      /// Generates a fresh random Nonce. Unless required by a specification to provide a specific Nonce, this is the recommended initializer.
      public init() {
        var data = Data(repeating: 0, count: Nonce.byteCount)
        data.withUnsafeMutableBytes {
          assert($0.count == Nonce.byteCount)
          $0.initializeWithRandomBytes(count: Nonce.byteCount)
        }
        self.bytes = data
      }

      public init<D>(data: D) throws where D: DataProtocol {
        guard data.count >= Nonce.byteCount else {
          throw CryptoKitError.incorrectParameterSize
        }

        self.bytes = Data(data.prefix(Nonce.byteCount))
      }

      public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try self.bytes.withUnsafeBytes(body)
      }

      public func makeIterator() -> Iterator {
        self.withUnsafeBytes({ (buffPtr) in
          return Array(buffPtr).makeIterator()
        })
      }
    }

    /// Encrypts data using AES-128-CFB without padding.
    ///
    /// - Parameters:
    ///   - message: The message to encrypt
    ///   - key: An encryption key of 128 bits
    ///   - nonce: An Nonce for AES-CFB encryption. It can be safely generated with AES.CFB.Nonce()
    /// - Returns: Encrypted data if success.
    public static func encrypt<Plaintext>(
      _ message: Plaintext,
      using key: SymmetricKey,
      nonce: Nonce
    ) throws -> Data where Plaintext: DataProtocol {
      try AESCFBImpl.encrypt(message, using: key, nonce: nonce)
    }

    /// Decrypts data using AES-128-ECB without padding.
    ///
    /// - Parameters:
    ///   - message: The message to decrypt
    ///   - key: An decryption key of 128 bits
    ///   - nonce: An Nonce for AES-CFB encryption. It can be safely generated with AES.CFB.Nonce().
    /// - Returns: Decrypted data if success.
    public static func decrypt<Ciphertext>(
      _ message: Ciphertext,
      using key: SymmetricKey,
      nonce: Nonce
    ) throws -> Data where Ciphertext: DataProtocol {
      try AESCFBImpl.decrypt(message, using: key, nonce: nonce)
    }
  }
}
