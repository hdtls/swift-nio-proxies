//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2021 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

@_implementationOnly import CNIOBoringSSL
import Crypto
import Foundation
import NEPrettyBytes

protocol DigestPrivate: Digest {
  init?(bufferPointer: UnsafeRawBufferPointer)
}

protocol HashFunctionImplementationDetails: HashFunction where Digest: DigestPrivate {}

protocol BoringSSLBackedHashFunction: HashFunctionImplementationDetails {
  static var digestType: DigestContext.DigestType { get }
}

extension SHA224: BoringSSLBackedHashFunction {
  static var digestType: DigestContext.DigestType {
    return .sha224
  }
}

struct OpenSSLDigestImpl<H: BoringSSLBackedHashFunction> {
  private var context: DigestContext

  init() {
    self.context = DigestContext(digest: H.digestType)
  }

  internal mutating func update(data: UnsafeRawBufferPointer) {
    if !isKnownUniquelyReferenced(&self.context) {
      self.context = DigestContext(copying: self.context)
    }
    self.context.update(data: data)
  }

  internal func finalize() -> H.Digest {
    // To have a non-destructive finalize operation we must allocate.
    let copyContext = DigestContext(copying: self.context)
    let digestBytes = copyContext.finalize()
    return digestBytes.withUnsafeBytes {
      // We force unwrap here because if the digest size is wrong it's an internal error.
      H.Digest(bufferPointer: $0)!
    }
  }
}
typealias DigestImpl = OpenSSLDigestImpl

class DigestContext {
  private var contextPointer: UnsafeMutablePointer<EVP_MD_CTX>

  init(digest: DigestType) {
    // We force unwrap because we cannot recover from allocation failure.
    self.contextPointer = CNIOBoringSSL_EVP_MD_CTX_new()!
    guard CNIOBoringSSL_EVP_DigestInit(self.contextPointer, digest.dispatchTable) != 0 else {
      // We can't do much but crash here.
      fatalError("Unable to initialize digest state: \(CNIOBoringSSL_ERR_get_error())")
    }
  }

  init(copying original: DigestContext) {
    // We force unwrap because we cannot recover from allocation failure.
    self.contextPointer = CNIOBoringSSL_EVP_MD_CTX_new()!
    guard CNIOBoringSSL_EVP_MD_CTX_copy(self.contextPointer, original.contextPointer) != 0
    else {
      // We can't do much but crash here.
      fatalError("Unable to copy digest state: \(CNIOBoringSSL_ERR_get_error())")
    }
  }

  func update(data: UnsafeRawBufferPointer) {
    guard let baseAddress = data.baseAddress else {
      return
    }

    CNIOBoringSSL_EVP_DigestUpdate(self.contextPointer, baseAddress, data.count)
  }

  // This finalize function is _destructive_: do not call it if you want to reuse the object!
  func finalize() -> [UInt8] {
    let digestSize = CNIOBoringSSL_EVP_MD_size(self.contextPointer.pointee.digest)
    var digestBytes = Array(repeating: UInt8(0), count: digestSize)
    var count = UInt32(digestSize)

    digestBytes.withUnsafeMutableBufferPointer { digestPointer in
      assert(digestPointer.count == count)
      CNIOBoringSSL_EVP_DigestFinal(self.contextPointer, digestPointer.baseAddress, &count)
    }

    return digestBytes
  }

  deinit {
    CNIOBoringSSL_EVP_MD_CTX_free(self.contextPointer)
  }
}

extension DigestContext {
  struct DigestType {
    var dispatchTable: OpaquePointer

    private init(_ dispatchTable: OpaquePointer) {
      self.dispatchTable = dispatchTable
    }

    static let sha224 = DigestType(CNIOBoringSSL_EVP_sha224())
  }
}

struct SHA224Digest: DigestPrivate {

  let bytes: (UInt64, UInt64, UInt64, UInt64, UInt64)

  init?(bufferPointer: UnsafeRawBufferPointer) {
    guard bufferPointer.count == Self.byteCount else {
      return nil
    }

    var bytes = (UInt64(0), UInt64(0), UInt64(0), UInt64(0), UInt64(0))
    withUnsafeMutableBytes(of: &bytes) { targetPtr in
      targetPtr.copyMemory(from: bufferPointer)
    }
    self.bytes = bytes
  }

  static var byteCount: Int {
    return 28
  }

  func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
    return try Swift.withUnsafeBytes(of: bytes) {
      let boundsCheckedPtr = UnsafeRawBufferPointer(
        start: $0.baseAddress,
        count: Self.byteCount
      )
      return try body(boundsCheckedPtr)
    }
  }

  private func toArray() -> ArraySlice<UInt8> {
    var array = [UInt8]()
    array.appendByte(bytes.0)
    array.appendByte(bytes.1)
    array.appendByte(bytes.2)
    array.appendByte(bytes.3)
    array.appendByte(bytes.4)
    return array.prefix(upTo: SHA224Digest.byteCount)
  }

  var description: String {
    return "\("SHA224") digest: \(toArray().hexString)"
  }

  func hash(into hasher: inout Hasher) {
    self.withUnsafeBytes { hasher.combine(bytes: $0) }
  }
}

/// The SHA-224 Hash Function
struct SHA224: HashFunctionImplementationDetails {
  static var blockByteCount: Int {
    get { return 64 }

    set { fatalError("Cannot set SHA224.blockByteCount") }
  }
  static var byteCount: Int {
    get { return 28 }

    set { fatalError("Cannot set SHA224.byteCount") }
  }
  typealias Digest = SHA224Digest

  var impl: DigestImpl<SHA224>

  /// Initializes the hash function instance.
  init() {
    impl = DigestImpl()
  }

  mutating func update(bufferPointer: UnsafeRawBufferPointer) {
    impl.update(data: bufferPointer)
  }

  func finalize() -> Self.Digest {
    return impl.finalize()
  }
}
