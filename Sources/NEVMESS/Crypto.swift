//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2022 Junfeng Zhang and the Netbot project authors
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

#if canImport(CommonCrypto)
@_implementationOnly import CommonCrypto
#else
@_implementationOnly import CCryptoBoringSSL
#endif

/// Swift version FNV-1a for 32 bits.
func commonFNV1a<Bytes: Sequence>(_ data: Bytes) -> UInt32 where Bytes.Element == UInt8 {
  // These are the FNV-1a parameters for 32 bits.
  let prime: UInt32 = 16_777_619
  let initialResult: UInt32 = 2_166_136_261

  return data.reduce(initialResult) { partialResult, byte in
    var partialResult = partialResult
    partialResult ^= UInt32(byte)
    partialResult &*= prime
    return partialResult
  }
}

func commonFNV1a(_ ptr: UnsafeRawBufferPointer) -> UInt32 {
  commonFNV1a(Array(ptr))
}

func commonAESCFB128Encrypt<Key>(
  nonce: [UInt8],
  key: Key,
  dataIn: UnsafeRawBufferPointer,
  dataOut: UnsafeMutableRawBufferPointer,
  dataOutAvailable: Int,
  dataOutMoved: UnsafeMutablePointer<Int>? = nil
) throws where Key: ContiguousBytes {
  try commonAESCFB128Crypt(
    enc: true,
    nonce: nonce,
    key: key,
    dataIn: dataIn,
    dataOut: dataOut,
    dataOutAvailable: dataOutAvailable,
    dataOutMoved: dataOutMoved
  )
}

func commonAESCFB128Decrypt<Key>(
  nonce: [UInt8],
  key: Key,
  dataIn: UnsafeRawBufferPointer,
  dataOut: UnsafeMutableRawBufferPointer,
  dataOutAvailable: Int,
  dataOutMoved: UnsafeMutablePointer<Int>? = nil
) throws where Key: ContiguousBytes {
  try commonAESCFB128Crypt(
    enc: false,
    nonce: nonce,
    key: key,
    dataIn: dataIn,
    dataOut: dataOut,
    dataOutAvailable: dataOutAvailable,
    dataOutMoved: dataOutMoved
  )
}

func commonAESEncrypt<Key>(
  key: Key,
  dataIn: UnsafeRawBufferPointer,
  dataOut: UnsafeMutableRawBufferPointer,
  dataOutAvailable: Int,
  dataOutMoved: UnsafeMutablePointer<Int>? = nil
) throws where Key: ContiguousBytes {
  try commonAESCrypt(
    enc: true,
    key: key,
    dataIn: dataIn,
    dataOut: dataOut,
    dataOutAvailable: dataOutAvailable,
    dataOutMoved: dataOutMoved
  )
}

func commonAESDecrypt<Key>(
  key: Key,
  dataIn: UnsafeRawBufferPointer,
  dataOut: UnsafeMutableRawBufferPointer,
  dataOutAvailable: Int,
  dataOutMoved: UnsafeMutablePointer<Int>? = nil
) throws where Key: ContiguousBytes {
  try commonAESCrypt(
    enc: false,
    key: key,
    dataIn: dataIn,
    dataOut: dataOut,
    dataOutAvailable: dataOutAvailable,
    dataOutMoved: dataOutMoved
  )
}

private func commonAESCFB128Crypt<Key>(
  enc: Bool,
  nonce: [UInt8],
  key: Key,
  dataIn: UnsafeRawBufferPointer,
  dataOut: UnsafeMutableRawBufferPointer,
  dataOutAvailable: Int,
  dataOutMoved: UnsafeMutablePointer<Int>?
) throws where Key: ContiguousBytes {
  #if canImport(CommonCrypto)
  var dataOutAvailable = dataOutAvailable
  var cryptor: CCCryptorRef?
  var retval: CCCryptorStatus
  //    var updateLen = 0
  //    var finalLen = 0

  retval = nonce.withUnsafeBytes { iv in
    key.withUnsafeBytes {
      CCCryptorCreateWithMode(
        CCOperation(enc ? kCCEncrypt : kCCDecrypt),
        CCMode(kCCModeCFB),
        CCAlgorithm(kCCAlgorithmAES),
        CCPadding(ccNoPadding),
        iv.baseAddress,
        $0.baseAddress,
        16,
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

  let dataInLength = dataIn.count
  let needed = CCCryptorGetOutputLength(cryptor, dataInLength, true)
  dataOutMoved?.pointee = needed

  guard needed <= dataOutAvailable else {
    CCCryptorRelease(cryptor)
    throw CryptoKitError.underlyingCoreCryptoError(error: Int32(retval))
  }

  retval = CCCryptorUpdate(
    cryptor,
    dataIn.baseAddress,
    dataInLength,
    dataOut.baseAddress,
    dataOutAvailable,
    dataOutMoved
  )

  guard retval == kCCSuccess else {
    CCCryptorRelease(cryptor)
    throw CryptoKitError.underlyingCoreCryptoError(error: Int32(retval))
  }

  //    dataOut += updateLen
  //    dataOutAvailable -= updateLen
  //    retval = CCCryptorFinal(cryptor, dataOut.baseAddress, dataOutAvailable, &finalLen)
  //    dataOutMoved?.pointee = updateLen + finalLen

  CCCryptorRelease(cryptor)
  #else
  let symmetricKey = UnsafeMutablePointer<AES_KEY>.allocate(
    capacity: MemoryLayout<AES_KEY>.size
  )
  symmetricKey.initialize(to: .init())
  defer {
    symmetricKey.deinitialize(count: MemoryLayout<AES_KEY>.size)
    symmetricKey.deallocate()
  }

  let status = key.withUnsafeBytes {
    CCryptoBoringSSL_AES_set_encrypt_key(
      $0.bindMemory(to: UInt8.self).baseAddress,
      128,
      symmetricKey
    )
  }
  guard status == 0 else {
    throw CryptoKitError.underlyingCoreCryptoError(
      error: Int32(CCryptoBoringSSL_ERR_get_error())
    )
  }

  var num: Int32 = 0
  var nonce = nonce
  nonce.withUnsafeMutableBytes { iv in
    CCryptoBoringSSL_AES_cfb128_encrypt(
      dataIn.bindMemory(to: UInt8.self).baseAddress,
      dataOut.bindMemory(to: UInt8.self).baseAddress,
      dataOutAvailable,
      symmetricKey,
      iv.bindMemory(to: UInt8.self).baseAddress,
      &num,
      enc ? AES_ENCRYPT : AES_DECRYPT
    )
  }
  #endif
}

private func commonAESCrypt<Key>(
  enc: Bool,
  key: Key,
  dataIn: UnsafeRawBufferPointer,
  dataOut: UnsafeMutableRawBufferPointer,
  dataOutAvailable: Int,
  dataOutMoved: UnsafeMutablePointer<Int>?
) throws where Key: ContiguousBytes {
  #if canImport(CommonCrypto)
  let status = key.withUnsafeBytes { k in
    CCCrypt(
      CCOperation(enc ? kCCEncrypt : kCCDecrypt),
      CCAlgorithm(kCCAlgorithmAES128),
      CCOptions(kCCOptionPKCS7Padding | kCCOptionECBMode),
      k.baseAddress,
      kCCKeySizeAES128,
      nil,
      dataIn.baseAddress,
      dataIn.count,
      dataOut.baseAddress,
      dataOutAvailable,
      dataOutMoved
    )
  }
  guard status == kCCSuccess else {
    throw CryptoKitError.underlyingCoreCryptoError(error: status)
  }
  #else
  let symmetricKey = UnsafeMutablePointer<AES_KEY>.allocate(
    capacity: MemoryLayout<AES_KEY>.size
  )
  symmetricKey.initialize(to: .init())
  defer {
    symmetricKey.deinitialize(count: MemoryLayout<AES_KEY>.size)
    symmetricKey.deallocate()
  }

  let status = key.withUnsafeBytes {
    CCryptoBoringSSL_AES_set_encrypt_key(
      $0.bindMemory(to: UInt8.self).baseAddress,
      128,
      symmetricKey
    )
  }
  guard status == 0 else {
    throw CryptoKitError.underlyingCoreCryptoError(
      error: Int32(CCryptoBoringSSL_ERR_get_error())
    )
  }

  enc
    ? CCryptoBoringSSL_AES_encrypt(
      dataIn.baseAddress,
      dataOut.baseAddress,
      symmetricKey
    )
    : CCryptoBoringSSL_AES_decrypt(
      dataIn.baseAddress,
      dataOut.baseAddress,
      symmetricKey
    )
  #endif
}
