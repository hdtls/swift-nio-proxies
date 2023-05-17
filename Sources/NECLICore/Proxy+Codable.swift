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

@_exported import NECore

extension Proxy: Codable {

  private enum CodingKeys: CodingKey {
    case serverAddress
    case port
    case `protocol`
    case username
    case password
    case authenticationRequired
    case prefererHttpTunneling
    case skipCertificateVerification
    case sni
    case certificatePinning
    case algorithm
    case overTls
    case overWebSocket
    case webSocketPath
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let serverAddress = try container.decode(String.self, forKey: .serverAddress)
    let port = try container.decode(Int.self, forKey: .port)
    let `protocol` = try container.decode(`Protocol`.self, forKey: .protocol)
    let username = try container.decodeIfPresent(String.self, forKey: .username)
    let password = try container.decodeIfPresent(String.self, forKey: .password)
    let authenticationRequired = try container.decodeIfPresent(
      Bool.self,
      forKey: .authenticationRequired
    )
    let prefererHttpTunneling = try container.decodeIfPresent(
      Bool.self,
      forKey: .prefererHttpTunneling
    )
    let skipCertificateVerification = try container.decodeIfPresent(
      Bool.self,
      forKey: .skipCertificateVerification
    )
    let sni = try container.decodeIfPresent(String.self, forKey: .sni)
    let certificatePinning = try container.decodeIfPresent(
      String.self,
      forKey: .certificatePinning
    )
    let algorithm = try container.decodeIfPresent(Algorithm.self, forKey: .algorithm)
    let overTls = try container.decodeIfPresent(Bool.self, forKey: .overTls)
    let overWebSocket = try container.decodeIfPresent(Bool.self, forKey: .overWebSocket)
    let webSocketPath = try container.decodeIfPresent(String.self, forKey: .webSocketPath)

    self.init(
      serverAddress: serverAddress,
      port: port,
      protocol: `protocol`,
      username: username ?? "",
      password: password ?? "",
      authenticationRequired: authenticationRequired ?? false,
      prefererHttpTunneling: prefererHttpTunneling ?? false,
      overTls: overTls ?? false,
      overWebSocket: overWebSocket ?? false,
      webSocketPath: webSocketPath ?? "",
      skipCertificateVerification: skipCertificateVerification ?? false,
      sni: sni ?? "",
      certificatePinning: certificatePinning ?? "",
      algorithm: algorithm ?? .aes128Gcm
    )
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(self.serverAddress, forKey: .serverAddress)
    try container.encode(self.port, forKey: .port)
    try container.encode(self.protocol, forKey: .protocol)

    // The properties listed below are not required by all protocols, and we should not encode
    // them in the result of the corresponding protocol.

    if !self.username.isEmpty {
      try container.encode(self.username, forKey: .username)
    }
    if !self.password.isEmpty {
      try container.encode(self.password, forKey: .password)
    }
    if self.authenticationRequired {
      try container.encode(self.authenticationRequired, forKey: .authenticationRequired)
    }
    if self.prefererHttpTunneling {
      try container.encode(self.prefererHttpTunneling, forKey: .prefererHttpTunneling)
    }
    if self.skipCertificateVerification {
      try container.encode(
        self.skipCertificateVerification,
        forKey: .skipCertificateVerification
      )
    }
    if !self.sni.isEmpty {
      try container.encode(self.sni, forKey: .sni)
    }
    if !self.certificatePinning.isEmpty {
      try container.encode(self.certificatePinning, forKey: .certificatePinning)
    }
    if self.algorithm != .aes128Gcm {
      try container.encode(self.algorithm, forKey: .algorithm)
    }
    if self.overTls {
      try container.encode(self.overTls, forKey: .overTls)
    }
    if self.overWebSocket {
      try container.encode(self.overWebSocket, forKey: .overWebSocket)
    }
    if !self.webSocketPath.isEmpty {
      try container.encode(self.webSocketPath, forKey: .webSocketPath)
    }
  }
}

extension Algorithm: Codable {}

extension Proxy.`Protocol`: Codable {}

extension Proxy: Equatable, Hashable {

  public static func == (lhs: Proxy, rhs: Proxy) -> Bool {
    lhs.serverAddress == rhs.serverAddress
      && lhs.port == rhs.port
      && lhs.protocol == rhs.protocol
      && lhs.username == rhs.username
      && lhs.password == rhs.password
      && lhs.authenticationRequired == rhs.authenticationRequired
      && lhs.prefererHttpTunneling == rhs.prefererHttpTunneling
      && lhs.overTls == rhs.overTls
      && lhs.skipCertificateVerification == rhs.skipCertificateVerification
      && lhs.sni == rhs.sni
      && lhs.certificatePinning == rhs.certificatePinning
      && lhs.algorithm == rhs.algorithm
  }

  public func hash(into hasher: inout Hasher) {
    hasher.combine(serverAddress)
    hasher.combine(port)
    hasher.combine(`protocol`)
    hasher.combine(username)
    hasher.combine(password)
    hasher.combine(authenticationRequired)
    hasher.combine(prefererHttpTunneling)
    hasher.combine(overTls)
    hasher.combine(skipCertificateVerification)
    hasher.combine(sni)
    hasher.combine(certificatePinning)
    hasher.combine(algorithm)
  }
}
