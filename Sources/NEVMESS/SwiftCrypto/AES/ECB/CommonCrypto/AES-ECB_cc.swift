//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2023 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#if canImport(CommonCrypto)
  import Crypto
  import Foundation
  @_implementationOnly import CommonCrypto

  enum CommonCryptoAESECBImpl {

    static func encrypt<Plaintext>(
      _ message: Plaintext,
      using key: SymmetricKey
    ) throws -> Data where Plaintext: DataProtocol {
      try execute(CCOperation(kCCEncrypt), message, using: key)
    }

    static func decrypt<Ciphertext>(
      _ message: Ciphertext,
      using key: SymmetricKey
    ) throws -> Data where Ciphertext: DataProtocol {
      try execute(CCOperation(kCCDecrypt), message, using: key)
    }
  }

  extension CommonCryptoAESECBImpl {

    private static func execute<Message>(
      _ operation: CCOperation,
      _ message: Message,
      using key: SymmetricKey
    ) throws -> Data where Message: DataProtocol {
      guard key.bitCount == SymmetricKeySize.bits128.bitCount else {
        throw CryptoKitError.incorrectKeySize
      }

      var cryptor: CCCryptorRef?
      var retval: CCCryptorStatus
      var updateLen = 0
      var finalLen = 0

      retval = key.withUnsafeBytes {
        CCCryptorCreate(
          operation,
          CCAlgorithm(kCCAlgorithmAES128),
          CCOptions(kCCOptionECBMode | kCCOptionPKCS7Padding),
          $0.baseAddress,
          key.bitCount / 8,
          nil,
          &cryptor
        )
      }
      guard retval == kCCSuccess else {
        throw CryptoKitError.underlyingCoreCryptoError(error: Int32(retval))
      }

      let dataInLength = message.count
      let needed = CCCryptorGetOutputLength(cryptor, dataInLength, true)
      var dataOutMoved = needed
      var dataOutAvailable = needed

      var dataOut = Data(repeating: .zero, count: dataOutAvailable)

      retval = withUnsafeMutablePointer(to: &dataOutMoved) { dataOutMoved in
        dataOut.withUnsafeMutableBytes { dataOut in
          Array(message).withUnsafeBytes { dataIn in
            CCCryptorUpdate(
              cryptor,
              dataIn.baseAddress,
              dataInLength,
              dataOut.baseAddress,
              dataOutAvailable,
              &updateLen
            )
          }
        }
      }

      guard retval == kCCSuccess else {
        CCCryptorRelease(cryptor)
        throw CryptoKitError.underlyingCoreCryptoError(error: Int32(retval))
      }

      dataOutAvailable -= updateLen
      retval = dataOut.withUnsafeMutableBytes { dataOut in
        CCCryptorFinal(
          cryptor,
          dataOut.baseAddress?.advanced(by: updateLen),
          dataOutAvailable,
          &finalLen
        )
      }
      dataOutMoved = updateLen + finalLen

      CCCryptorRelease(cryptor)
      return dataOut.prefix(dataOutMoved)
    }
  }
#endif
