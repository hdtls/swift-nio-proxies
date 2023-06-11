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

    public typealias SealedBox = Data

    public struct Nonce: ContiguousBytes, Sequence {

      private let bytes: Data

      private static let byteCount = 16

      /// Generates a fresh random Nonce. Unless required by a specification to provide a specific Nonce, this is the recommended initializer.
      public init() {
        var data = Data(repeating: 0, count: Nonce.byteCount)
        data.withUnsafeMutableBytes {
          assert($0.count == Nonce.byteCount)
          $0.initializeWithRandomBytes(count: Nonce.byteCount)
        }
        self.bytes = data
      }

      public init<D: DataProtocol>(data: D) throws {
        guard data.count >= Nonce.byteCount else {
          throw CryptoKitError.incorrectParameterSize
        }

        self.bytes = Data(data.prefix(Nonce.byteCount))
      }

      public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try self.bytes.withUnsafeBytes(body)
      }

      public func makeIterator() -> Array<UInt8>.Iterator {
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
    ///   - nonce: An Nonce for AES-CFB encryption. The nonce must be unique for every use of the key to seal data. It can be safely generated with AES.CFB.Nonce()
    /// - Returns: A sealed box returning the ciphertext
    public static func seal<Plaintext: DataProtocol>(
      _ message: Plaintext,
      using key: SymmetricKey,
      nonce: Nonce
    ) throws -> SealedBox {
      try AESCFBImpl.seal(message, using: key, nonce: nonce)
    }

    /// Decrypts data using AES-128-ECB without padding.
    ///
    /// - Parameters:
    ///   - sealedBox: The sealed box to decrypt
    ///   - key: An encryption key of 128 bits
    ///   - nonce: An Nonce for AES-CFB encryption. The nonce must be unique for every use of the key to seal data. It can be safely generated with AES.CFB.Nonce().
    /// - Returns: The ciphertext if opening was successful
    public static func open(_ sealedBox: SealedBox, using key: SymmetricKey, nonce: Nonce) throws
      -> Data
    {
      try AESCFBImpl.open(sealedBox, using: key, nonce: nonce)
    }
  }
}
