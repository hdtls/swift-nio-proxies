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

struct OpenSSLAESCFBImpl {

  typealias SealedBox = Data

  static func seal<Plaintext: DataProtocol>(
    _ message: Plaintext,
    using key: SymmetricKey,
    nonce: AES.CFB.Nonce
  ) throws -> SealedBox {
    try execute(AES_ENCRYPT, message, using: key, nonce: nonce)
  }

  static func open(_ sealedBox: SealedBox, using key: SymmetricKey, nonce: AES.CFB.Nonce) throws
    -> Data
  {
    try execute(AES_DECRYPT, sealedBox, using: key, nonce: nonce)
  }
}

extension OpenSSLAESCFBImpl {

  private static func execute<Message: DataProtocol>(
    _ operation: Int32,
    _ message: Message,
    using key: SymmetricKey,
    nonce: AES.CFB.Nonce
  ) throws -> SealedBox {
    precondition(operation == AES_ENCRYPT || operation == AES_DECRYPT)
    guard key.bitCount == SymmetricKeySize.bits128.bitCount else {
      throw CryptoKitError.incorrectKeySize
    }

    let symmetricKey = UnsafeMutablePointer<AES_KEY>.allocate(
      capacity: MemoryLayout<AES_KEY>.size
    )
    symmetricKey.initialize(to: .init())
    defer {
      symmetricKey.deinitialize(count: MemoryLayout<AES_KEY>.size)
      symmetricKey.deallocate()
    }

    let retval = key.withUnsafeBytes {
      CCryptoBoringSSL_AES_set_encrypt_key(
        $0.bindMemory(to: UInt8.self).baseAddress,
        UInt32(key.bitCount),
        symmetricKey
      )
    }
    guard retval == 0 else {
      throw CryptoKitError.underlyingCoreCryptoError(
        error: Int32(CCryptoBoringSSL_ERR_get_error())
      )
    }

    var numRounds: Int32 = 0
    let dataOutMoved = message.count

    var dataOut = Data(repeating: .zero, count: dataOutMoved)

    var copy = Array(nonce)
    copy.withUnsafeMutableBufferPointer { nonce in
      dataOut.withUnsafeMutableBytes { dataOut in
        Array(message).withUnsafeBufferPointer { dataIn in
          CCryptoBoringSSL_AES_cfb128_encrypt(
            dataIn.baseAddress,
            dataOut.bindMemory(to: UInt8.self).baseAddress,
            dataOutMoved,
            symmetricKey,
            nonce.baseAddress,
            &numRounds,
            operation
          )
        }
      }
    }

    return dataOut.prefix(dataOutMoved)
  }
}
#endif
