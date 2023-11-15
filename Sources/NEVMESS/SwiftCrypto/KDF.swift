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

private protocol HashFunction {

  static var blockSize: Int { get }

  mutating func update(bufferPointer: UnsafeRawBufferPointer)

  mutating func update<D: DataProtocol>(data: D)

  func _finalize() -> [UInt8]
}

extension SHA256: HashFunction {

  fileprivate static let blockSize: Int = 64

  fileprivate func _finalize() -> [UInt8] {
    Array(finalize())
  }
}

struct KDF {

  private struct HMAC: HashFunction {

    static var blockSize: Int { SHA256.blockSize }

    mutating func update(bufferPointer: UnsafeRawBufferPointer) {
      innerHasher.update(bufferPointer: bufferPointer)
    }

    mutating func update<D: DataProtocol>(data: D) {
      data.regions.forEach { (regionData) in
        regionData.withUnsafeBytes({ (dataPtr) in
          self.update(bufferPointer: dataPtr)
        })
      }
    }

    func _finalize() -> [UInt8] {
      let buffer = innerHasher._finalize()
      var outerHashForFinalization = outerHasher
      buffer.withUnsafeBytes {
        outerHashForFinalization.update(bufferPointer: $0)
      }
      return outerHashForFinalization._finalize()
    }

    var outerHasher: HashFunction
    var innerHasher: HashFunction

    init<U: HashFunction>(_ H: @autoclosure () -> U, key: SymmetricKey) {
      var k: ContiguousBytes

      if key.withUnsafeBytes({ $0.count }) == U.blockSize {
        k = key
      } else if key.withUnsafeBytes({ $0.count }) > U.blockSize {
        k = key.withUnsafeBytes { (keyBytes) in
          var hash = H()
          hash.update(bufferPointer: keyBytes)
          return hash._finalize()
        }
      } else {
        var keyArray = Array(repeating: UInt8(0), count: U.blockSize)
        key.withUnsafeBytes { keyArray.replaceSubrange(0..<$0.count, with: $0) }
        k = keyArray
      }

      self.innerHasher = H()
      let innerKey = k.withUnsafeBytes {
        return $0.map({ (keyByte) in
          keyByte ^ 0x36
        })
      }
      innerHasher.update(data: innerKey)

      self.outerHasher = H()
      let outerKey = k.withUnsafeBytes {
        return $0.map({ (keyByte) in
          keyByte ^ 0x5c
        })
      }
      outerHasher.update(data: outerKey)
    }
  }

  /// Derives a symmetric key using the KDF algorithm.
  ///
  /// - Parameters:
  ///   - inputKeyMaterial: Input key material.
  ///   - paths: path list.
  ///   - outputByteCount: The desired number of output bit count, defaults to 16 bytes.
  /// - Returns: The derived key
  static func deriveKey<Info>(
    inputKeyMaterial: SymmetricKey,
    info: [Info],
    outputByteCount: Int = 16
  ) -> SymmetricKey where Info: DataProtocol {
    let kDFSaltConstVMessAEADKDF = Data("VMess AEAD KDF".utf8)

    var hasher = HMAC(SHA256(), key: .init(data: kDFSaltConstVMessAEADKDF))

    for path in info {
      hasher = HMAC(hasher, key: .init(data: Array(path)))
    }
    inputKeyMaterial.withUnsafeBytes {
      hasher.update(bufferPointer: $0)
    }

    return .init(data: hasher._finalize().prefix(outputByteCount))
  }

  static func deriveKey<Info>(
    inputKeyMaterial: SymmetricKey,
    info: Info,
    outputByteCount: Int = 16
  ) -> SymmetricKey where Info: DataProtocol {
    deriveKey(inputKeyMaterial: inputKeyMaterial, info: [info], outputByteCount: outputByteCount)
  }
}

func generateCmdKey(_ id: UUID) -> SymmetricKey {
  withUnsafeBytes(of: id) {
    var hasher = Insecure.MD5.init()
    hasher.update(bufferPointer: $0)
    hasher.update(data: Data("c48619fe-8f02-49e0-b9e9-edf763e17e21".utf8))
    return .init(data: hasher.finalize())
  }
}

func generateChaChaPolySymmetricKey(inputKeyMaterial: SymmetricKey) -> SymmetricKey {
  inputKeyMaterial.withUnsafeBytes {
    Insecure.MD5.hash(data: $0).withUnsafeBytes { pointer in
      SymmetricKey(data: Array(pointer) + Insecure.MD5.hash(data: pointer))
    }
  }
}
