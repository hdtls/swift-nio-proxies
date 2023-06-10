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

#if canImport(CommonCrypto)
import Crypto
import Foundation
@_implementationOnly import CommonCrypto

enum CommonCryptoAESCFBImpl {

  typealias SealedBox = Data

  static func seal<Plaintext: DataProtocol>(
    _ message: Plaintext,
    using key: SymmetricKey,
    nonce: AES.CFB.Nonce
  ) throws -> SealedBox {
    try execute(CCOperation(kCCEncrypt), message, using: key, nonce: nonce)
  }

  static func open(_ sealedBox: SealedBox, using key: SymmetricKey, nonce: AES.CFB.Nonce) throws
    -> Data
  {
    try execute(CCOperation(kCCDecrypt), sealedBox, using: key, nonce: nonce)
  }
}

extension CommonCryptoAESCFBImpl {

  private static func execute<Message: DataProtocol>(
    _ operation: CCOperation,
    _ message: Message,
    using key: SymmetricKey,
    nonce: AES.CFB.Nonce
  ) throws -> SealedBox {
    guard key.bitCount == SymmetricKeySize.bits128.bitCount else {
      throw CryptoKitError.incorrectKeySize
    }

    var cryptor: CCCryptorRef?
    var retval: CCCryptorStatus
    var updateLen = 0
    var finalLen = 0

    retval = nonce.withUnsafeBytes { iv in
      key.withUnsafeBytes {
        CCCryptorCreateWithMode(
          operation,
          CCMode(kCCModeCFB),
          CCAlgorithm(kCCAlgorithmAES),
          CCPadding(ccNoPadding),
          iv.baseAddress,
          $0.baseAddress,
          key.bitCount / 8,
          nil,
          0,
          0,
          CCModeOptions(kCCModeOptionCTR_BE),
          &cryptor
        )
      }
    }
    guard retval == kCCSuccess else {
      throw CryptoKitError.underlyingCoreCryptoError(error: Int32(retval))
    }

    let dataInLength = message.count
    let needed = CCCryptorGetOutputLength(cryptor, dataInLength, true)
    var dataOutMoved = needed
    var dataOutAvailable = needed

    var dataOut = Data(repeating: .zero, count: needed)

    retval = dataOut.withUnsafeMutableBytes { dataOut in
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
