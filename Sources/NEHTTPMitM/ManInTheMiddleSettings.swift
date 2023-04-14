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

/// Configuration for HTTPS traffic decraption with MitM attacks.
public struct ManInTheMiddleSettings: Sendable {

  /// A boolean value determinse whether ssl should skip server cerfitication verification. Default is false.
  public var skipCertificateVerification: Bool = false

  /// Hostnames that should perform MitM.
  public var hostnames: [String] = []

  /// Base64 encoded CA P12 bundle.
  public var base64EncodedP12String: String?

  /// Passphrase for P12 bundle.
  public var passphrase: String?

  /// Initialize an instance of `ManInTheMiddleSettings` with specified skipCertificateVerification, hostnames, base64EncodedP12String, passphrase.
  /// - Parameters:
  ///   - skipCertificateVerification: A boolean value determinse whether client should skip server certificate verification.
  ///   - hostnames: Hostnames use when decript.
  ///   - base64EncodedP12String: The base64 encoded p12 certificate bundle string.
  ///   - passphrase: Passphrase for p12 bundle.
  public init(
    skipCertificateVerification: Bool,
    hostnames: [String],
    base64EncodedP12String: String?,
    passphrase: String?
  ) {
    self.skipCertificateVerification = skipCertificateVerification
    self.hostnames = hostnames
    self.passphrase = passphrase
    self.base64EncodedP12String = base64EncodedP12String
  }

  /// Initialize an instance of `ManInTheMiddleSettings`.
  ///
  /// Calling this method is equivalent to calling
  /// `init(skipCertificateVerification:hostnames:base64EncodedP12String:passphrase:)`
  /// with a default skipCertificateVerification, hostnames, base64EncodedP12String and passphrase values.
  public init() {
    self.init(
      skipCertificateVerification: false,
      hostnames: [],
      base64EncodedP12String: nil,
      passphrase: nil
    )
  }
}
