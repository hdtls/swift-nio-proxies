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
@_exported import NIOSSL
import SwiftASN1
import X509
import _CryptoExtras

/// Certificate cache used to generate server certificate when perform HTTP MitM decryption.
public struct CertCache: @unchecked Sendable {

  public typealias CacheEntry = ([NIOSSLCertificateSource], NIOSSLPrivateKeySource)

  var entries: [String: CacheEntry] = [:]

  var hostnames: [String] = []

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

  private let certificate: Certificate

  private let privateKey: Certificate.PrivateKey

  private init(ref: OpaquePointer, passphrase: String?) throws {
    // <EVP_PKEY>
    var pkey: OpaquePointer? = nil

    // <X509>
    var cert: OpaquePointer? = nil
    var caCerts: OpaquePointer? = nil

    guard CNIOBoringSSL_PKCS12_parse(ref, passphrase, &pkey, &cert, &caCerts) == 1 else {
      let errorStack = BoringSSLError.buildErrorStack()
      throw BoringSSLError.unknownError(errorStack)
    }

    // Successfully parsed, let's unpack. The key and cert are mandatory,
    // the ca stack is not.
    guard let actualCert = cert, let actualKey = pkey else {
      fatalError("Failed to obtain cert and pkey from a PKC12 file")
    }

    // Read X509 certificate into DER bytes.
    guard let bio = CNIOBoringSSL_BIO_new(CNIOBoringSSL_BIO_s_mem()) else {
      fatalError("Failed to malloc for a BIO handler")
    }
    defer {
      CNIOBoringSSL_BIO_free(bio)
    }

    guard CNIOBoringSSL_i2d_X509_bio(bio, actualCert) == 1 else {
      let errorStack = BoringSSLError.buildErrorStack()
      throw BoringSSLError.unknownError(errorStack)
    }

    var dataPtr: UnsafeMutablePointer<CChar>? = nil
    var length = CNIOBoringSSL_BIO_get_mem_data(bio, &dataPtr)

    guard let bytes = dataPtr.map({ UnsafeRawBufferPointer(start: $0, count: length) }) else {
      fatalError("Failed to map bytes from a certificate")
    }

    self.certificate = try .init(derEncoded: Array(bytes))

    // Read EVP_PKEY into DER bytes.
    guard CNIOBoringSSL_BIO_reset(bio) == 1 else {
      let errorStack = BoringSSLError.buildErrorStack()
      throw BoringSSLError.unknownError(errorStack)
    }

    guard CNIOBoringSSL_i2d_PrivateKey_bio(bio, actualKey) == 1 else {
      let errorStack = BoringSSLError.buildErrorStack()
      throw BoringSSLError.unknownError(errorStack)
    }

    dataPtr = nil
    length = CNIOBoringSSL_BIO_get_mem_data(bio, &dataPtr)

    guard let bytes = dataPtr.map({ UnsafeRawBufferPointer(start: $0, count: length) }) else {
      fatalError("Failed to map bytes from a private key")
    }

    self.privateKey = .init(try _RSA.Signing.PrivateKey(derRepresentation: bytes))
  }

  /// Initialize an instance of `CertificateStore` with specified passphrase and base64 encoded p12 string.
  /// - Parameters:
  ///   - base64EncodedP12String: The base64 encoded p12 bundle string.
  ///   - passphrase: The passphrase for this p12 bundle.
  public init(base64EncodedP12String: String, passphrase: String? = nil) throws {
    guard let buffer = Data(base64Encoded: base64EncodedP12String) else {
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

  /// Initialize an instance of `CertCache` with specified `ManInTheMiddleSettings`.
  public init(manInTheMiddleSettings: ManInTheMiddleSettings) throws {
    guard let base64EncodedP12String = manInTheMiddleSettings.base64EncodedP12String else {
      // To enable the HTTP MitM feature, you must provide the corresponding configuration.
      throw NIOSSLError.failedToLoadCertificate
    }
    try self.init(
      base64EncodedP12String: base64EncodedP12String,
      passphrase: manInTheMiddleSettings.passphrase
    )
    self.hostnames = manInTheMiddleSettings.hostnames
  }

  /// Update MitM hostnames.
  /// - Parameter newValue: The hosts witch allow MitM decryption.
  public mutating func setUpMitMHosts(_ newValue: [String]) {
    lock.withLock {
      newValue.difference(from: hostnames).removals.forEach {
        switch $0 {
        case .insert(offset: _, element: _, associatedWith: _):
          break
        case .remove(offset: _, element: let host, associatedWith: _):
          entries.removeValue(forKey: host)
        }
      }
      hostnames = newValue
    }
  }

  private func cacheKey(for host: String) -> String? {
    hostnames.filter {
      guard $0.hasPrefix("*.") else {
        return $0 == host
      }
      return host.hasSuffix($0.suffix($0.count - 1))
    }.first
  }

  /// Find SSL source with hostname.
  /// - Parameter key: The key identified ssl source in cert cache.
  /// - Returns: The certificate source and private key source if find or nil.
  public mutating func value(forKey key: String) throws -> CacheEntry? {
    try lock.withLock {
      guard let key = cacheKey(for: key) else {
        return nil
      }

      guard entries[key] == nil else {
        return entries[key]
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
        issuer: self.certificate.subject,
        subject: subject,
        signatureAlgorithm: .sha256WithRSAEncryption,
        extensions: extensions,
        issuerPrivateKey: self.privateKey
      )

      var serializer = DER.Serializer()
      try serializer.serialize(certificate)

      let cacheEntry = (
        [
          NIOSSLCertificateSource.certificate(
            try .init(bytes: serializer.serializedBytes, format: .der)
          )
        ],
        NIOSSLPrivateKeySource.privateKey(
          try .init(bytes: Array(privateKey.derRepresentation), format: .der)
        )
      )

      entries[key] = cacheEntry
      return cacheEntry
    }
  }

  /// Remove a value  from the cache and return it
  @discardableResult
  public mutating func removeValue(forKey key: String) -> CacheEntry? {
    lock.withLock {
      guard let key = cacheKey(for: key) else {
        return nil
      }
      return entries.removeValue(forKey: key)
    }
  }

  /// Remove all values from the cache
  public mutating func removeAllValues() {
    lock.withLock {
      entries.removeAll()
    }
  }
}
