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

public protocol ManInTheMiddleSettingsRepresentation: Hashable, Sendable {

  /// A boolean value determinse whether ssl should skip server cerfitication verification. Default is false.
  var skipCertificateVerification: Bool { get }

  /// Hostnames that should perform MitM.
  var hostnames: [String] { get }

  /// Base64 encoded CA P12 bundle.
  var base64EncodedP12String: String? { get }

  /// Passphrase for P12 bundle.
  var passphrase: String? { get }
}
