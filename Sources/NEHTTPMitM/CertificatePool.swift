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

@_implementationOnly import CNIOBoringSSL
import Foundation
import NIOConcurrencyHelpers
import NIOSSL
import SwiftASN1
import X509
import _CryptoExtras

/// Certificate pool used to generate server certificate when perform HTTP MitM decryption.
public class CertificatePool: @unchecked Sendable {

  public typealias CacheEntry = ([NIOSSLCertificateSource], NIOSSLPrivateKeySource)

  var entries: [String: CacheEntry] = [:]

  var keys: [String] = []

  /// A Boolean value that indicates whether the cache is empty.
  public var isEmpty: Bool {
    lock.withLock {
      entries.isEmpty
    }
  }

  /// The number of entries in the cache.
  public var count: Int {
    lock.withLock {
      entries.count
    }
  }

  private let lock = NIOLock()

  private let certificateChain: [Certificate]

  private let privateKey: Certificate.PrivateKey

  private init(ref: OpaquePointer, passphrase: String?) throws {
    var pkey: OpaquePointer? = nil
    var cert: OpaquePointer? = nil
    var caCerts: OpaquePointer? = nil

    let rc = passphrase?.withCString { passphrase in
      CNIOBoringSSL_PKCS12_parse(ref, passphrase, &pkey, &cert, &caCerts)
    }
    guard rc == 1 else {
      throw BoringSSLError.unknownError(BoringSSLError.buildErrorStack())
    }

    // Successfully parsed, let's unpack. The key and cert are mandatory,
    // the ca stack is not.
    guard let actualCert = cert, let actualKey = pkey else {
      fatalError("Failed to obtain cert and pkey from a PKC12 file")
    }

    let certStackSize = caCerts.map { CNIOBoringSSL_sk_X509_num($0) } ?? 0
    var certs = [Certificate]()
    certs.reserveCapacity(Int(certStackSize) + 1)
    certs.append(try .fromUnsafePointer(ref: actualCert))

    for idx in 0..<certStackSize {
      guard let stackCertPtr = CNIOBoringSSL_sk_X509_value(caCerts, idx) else {
        preconditionFailure("Unable to get cert \(idx) from stack \(String(describing: caCerts))")
      }
      certs.append(try .fromUnsafePointer(ref: stackCertPtr))
    }

    self.certificateChain = certs
    self.privateKey = .init(try _RSA.Signing.PrivateKey.fromUnsafePointer(ref: actualKey))
  }

  /// Initialize an instance of `CertificatePool` with specified passphrase and base64 encoded p12 string.
  /// - Parameters:
  ///   - base64Encoded: The base64 encoded p12 string.
  ///   - passphrase: The passphrase for this p12 bundle.
  public convenience init(base64Encoded base64String: String, passphrase: String? = nil) throws {
    guard let buffer = Data(base64Encoded: base64String) else {
      // To enable the HTTP MitM feature, you must provide the corresponding configuration.
      throw NIOSSLError.failedToLoadCertificate
    }

    let p12 = buffer.withUnsafeBytes { pointer -> OpaquePointer? in
      let bio = CNIOBoringSSL_BIO_new_mem_buf(pointer.baseAddress, pointer.count)!
      defer {
        CNIOBoringSSL_BIO_free(bio)
      }
      return CNIOBoringSSL_d2i_PKCS12_bio(bio, nil)
    }
    defer {
      p12.map { CNIOBoringSSL_PKCS12_free($0) }
    }

    guard let p12 = p12 else {
      throw BoringSSLError.unknownError(BoringSSLError.buildErrorStack())
    }

    try self.init(ref: p12, passphrase: passphrase)
  }

  private func cacheKey(for host: String) -> String? {
    keys.filter {
      guard $0.hasPrefix("*.") else {
        return $0 == host
      }
      return host.hasSuffix($0.suffix($0.count - 1))
    }.first
  }

  public func registerKeys(_ keys: [String]) {
    lock.withLock {
      keys.difference(from: self.keys).removals.forEach {
        switch $0 {
        case .insert(offset: _, element: _, associatedWith: _):
          break
        case .remove(offset: _, element: let host, associatedWith: _):
          entries.removeValue(forKey: host)
        }
      }
      self.keys = keys
    }
  }

  /// Find SSL source with hostname.
  /// - Parameter key: The key identified ssl source in cert pool.
  /// - Returns: The certificate source and private key source if find or nil.
  public func value(forKey key: String) throws -> CacheEntry? {
    guard let key = lock.withLock({ cacheKey(for: key) }), let caCert = certificateChain.last else {
      return nil
    }

    var cacheEntry = lock.withLock {
      entries[key]
    }
    guard cacheEntry == nil else {
      return cacheEntry
    }

    let privateKey = try _RSA.Signing.PrivateKey(keySize: .bits2048)

    let notValidBefore = Date()

    let subject = try DistinguishedName {
      CommonName(key)
    }

    let extensions = try Certificate.Extensions {
      SubjectAlternativeNames([.dnsName(key)])
    }

    let certificate = try Certificate(
      version: .v3,
      serialNumber: .init(),
      publicKey: .init(privateKey.publicKey),
      notValidBefore: notValidBefore,
      notValidAfter: notValidBefore.addingTimeInterval(60 * 60 * 24 * 30),
      issuer: caCert.subject,
      subject: subject,
      signatureAlgorithm: .sha256WithRSAEncryption,
      extensions: extensions,
      issuerPrivateKey: self.privateKey
    )

    var serializer = DER.Serializer()
    try serializer.serialize(certificate)

    cacheEntry = (
      [
        NIOSSLCertificateSource.certificate(
          try .init(bytes: serializer.serializedBytes, format: .der)
        )
      ],
      NIOSSLPrivateKeySource.privateKey(
        try .init(bytes: Array(privateKey.derRepresentation), format: .der)
      )
    )

    lock.withLock {
      entries[key] = cacheEntry
    }
    return cacheEntry
  }

  /// Remove a value  from the pool and return it
  @discardableResult
  public func removeValue(forKey key: String) -> CacheEntry? {
    lock.withLock {
      guard let key = cacheKey(for: key) else {
        return nil
      }
      return entries.removeValue(forKey: key)
    }
  }

  /// Remove all values from the pool
  public func removeAllValues() {
    lock.withLock {
      entries.removeAll()
    }
  }
}

extension Certificate {

  static func fromUnsafePointer(ref: OpaquePointer) throws -> Certificate {
    guard let bio = CNIOBoringSSL_BIO_new(CNIOBoringSSL_BIO_s_mem()) else {
      fatalError("Failed to malloc for a BIO handler")
    }

    defer {
      CNIOBoringSSL_BIO_free(bio)
    }

    let rc = CNIOBoringSSL_i2d_X509_bio(bio, ref)
    guard rc == 1 else {
      let errorStack = BoringSSLError.buildErrorStack()
      throw BoringSSLError.unknownError(errorStack)
    }

    var dataPtr: UnsafeMutablePointer<CChar>? = nil
    let length = CNIOBoringSSL_BIO_get_mem_data(bio, &dataPtr)

    guard let bytes = dataPtr.map({ UnsafeRawBufferPointer(start: $0, count: length) }) else {
      fatalError("Failed to map bytes from a certificate")
    }

    return try .init(derEncoded: Array(bytes))
  }
}

extension _RSA.Signing.PrivateKey {

  static func fromUnsafePointer(ref: OpaquePointer) throws -> _RSA.Signing.PrivateKey {
    guard let bio = CNIOBoringSSL_BIO_new(CNIOBoringSSL_BIO_s_mem()) else {
      fatalError("Failed to malloc for a BIO handler")
    }

    defer {
      CNIOBoringSSL_BIO_free(bio)
    }

    let rc = CNIOBoringSSL_i2d_PrivateKey_bio(bio, ref)
    guard rc == 1 else {
      let errorStack = BoringSSLError.buildErrorStack()
      throw BoringSSLError.unknownError(errorStack)
    }

    var dataPtr: UnsafeMutablePointer<CChar>? = nil
    let length = CNIOBoringSSL_BIO_get_mem_data(bio, &dataPtr)

    guard let bytes = dataPtr.map({ UnsafeRawBufferPointer(start: $0, count: length) }) else {
      fatalError("Failed to map bytes from a private key")
    }

    return try .init(derRepresentation: bytes)
  }
}
