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

#if !canImport(CommonCrypto)
import Crypto
import Foundation
@_implementationOnly import CCryptoBoringSSL

enum OpenSSLAESECBImpl {

  static func encrypt<Plaintext>(
    _ message: Plaintext,
    using key: SymmetricKey
  ) throws -> Data where Plaintext: DataProtocol {
    try execute(AES_ENCRYPT, message, using: key)
  }

  static func decrypt<Ciphertext>(
    _ message: Ciphertext,
    using key: SymmetricKey
  ) throws -> Data where Ciphertext: DataProtocol {
    try execute(AES_DECRYPT, message, using: key)
  }
}

extension OpenSSLAESECBImpl {

  fileprivate static func execute<Message>(
    _ operation: Int32,
    _ message: Message,
    using key: SymmetricKey
  ) throws -> Data where Message: DataProtocol {
    precondition(operation == AES_ENCRYPT || operation == AES_DECRYPT)
    guard key.bitCount == SymmetricKeySize.bits128.bitCount else {
      throw CryptoKitError.incorrectKeySize
    }

    let contextPointer = CCryptoBoringSSL_EVP_CIPHER_CTX_new()

    var retval = key.withUnsafeBytes { key in
      CCryptoBoringSSL_EVP_CipherInit_ex(
        contextPointer,
        CCryptoBoringSSL_EVP_aes_128_ecb(),
        nil,
        key.bindMemory(to: UInt8.self).baseAddress,
        nil,
        operation
      )
    }
    guard retval == 1 else {
      throw CryptoKitError.underlyingCoreCryptoError(error: Int32(CCryptoBoringSSL_ERR_get_error()))
    }

    CCryptoBoringSSL_EVP_CIPHER_CTX_set_padding(contextPointer, 1)

    var updateLen = Int32.zero
    var finalLen = Int32.zero

    let dataInLength = Int32(message.count)
    let needed = (Int32(message.count) + AES_BLOCK_SIZE) / AES_BLOCK_SIZE * AES_BLOCK_SIZE

    var dataOut = Data(repeating: .zero, count: Int(needed))

    retval = dataOut.withUnsafeMutableBytes { dataOut in
      Array(message).withUnsafeBufferPointer { dataIn in
        CCryptoBoringSSL_EVP_CipherUpdate(
          contextPointer,
          dataOut.bindMemory(to: UInt8.self).baseAddress,
          &updateLen,
          dataIn.baseAddress,
          dataInLength
        )
      }
    }
    guard retval == 1 else {
      throw CryptoKitError.underlyingCoreCryptoError(error: Int32(CCryptoBoringSSL_ERR_get_error()))
    }

    retval = dataOut.withUnsafeMutableBytes { dataOut in
      CCryptoBoringSSL_EVP_CipherFinal_ex(
        contextPointer,
        dataOut.bindMemory(to: UInt8.self).baseAddress?.advanced(by: Int(updateLen)),
        &finalLen
      )
    }
    guard retval == 1 else {
      throw CryptoKitError.underlyingCoreCryptoError(error: Int32(CCryptoBoringSSL_ERR_get_error()))
    }

    let dataOutMoved = updateLen + finalLen

    CCryptoBoringSSL_EVP_CIPHER_CTX_free(contextPointer)
    return dataOut.prefix(Int(dataOutMoved))
  }
}
#endif
