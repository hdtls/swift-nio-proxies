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

import NEAppEssentials
import NESS

/// A wrapper object use to decoding and encoding proxy settings.
public struct Proxy: Codable, Hashable, Sendable {

  /// Proxy protocol definition.
  public enum `Protocol`: String, CaseIterable, Codable, CustomStringConvertible, Sendable {
    case http
    case socks5
    case shadowsocks = "ss"
    case vmess

    public var description: String {
      switch self {
      case .http:
        return "HTTP"
      case .socks5:
        return "SOCKS5"
      case .shadowsocks:
        return "Shadowsocks"
      case .vmess:
        return "VMESS"
      }
    }
  }

  /// Proxy server address.
  public var serverAddress: String

  /// Proxy server port.
  public var port: Int

  /// Proxy protocol.
  public var `protocol`: `Protocol`

  /// Username for proxy authentication.
  ///
  /// - note: For VMESS protocol username *MUST* be an UUID string.
  public var username: String = ""

  /// Password for HTTP basic authentication and SOCKS5 username password authentication.
  public var passwordReference: String = ""

  /// A boolean value determinse whether connection should perform username password authentication.
  ///
  /// - note: This is used in HTTP/HTTPS basic authentication and SOCKS/SOCKS over TLS username/password authentication.
  public var authenticationRequired: Bool = false

  /// A boolean value determinse whether HTTP proxy should prefer using CONNECT tunnel.
  public var prefererHttpTunneling: Bool = false

  /// A boolean value determinse whether connection should enable TLS.
  public var overTls: Bool = false

  /// A boolean value determinse whether stream should transfer using `WebSocket` protocol.
  public var overWebSocket: Bool = false

  /// Path for `WebSocket`.
  public var webSocketPath: String = ""

  /// A boolean value determinse whether SSL should skip certification verification.
  public var skipCertificateVerification: Bool = false

  /// SSL sni.
  public var sni: String = ""

  /// SSL certificate pinning.
  public var certificatePinning: String = ""

  /// SS encryption and decryption algorithm.
  ///
  /// - note: This is used in Shadowsocks protocol.
  public var algorithm: Algorithm = .aes128Gcm

  public init(
    serverAddress: String,
    port: Int,
    `protocol`: `Protocol`,
    username: String = "",
    passwordReference: String = "",
    authenticationRequired: Bool = false,
    prefererHttpTunneling: Bool = false,
    overTls: Bool = false,
    overWebSocket: Bool = false,
    webSocketPath: String = "",
    skipCertificateVerification: Bool = false,
    sni: String = "",
    certificatePinning: String = "",
    algorithm: Algorithm = .aes128Gcm
  ) {
    self.serverAddress = serverAddress
    self.port = port
    self.protocol = `protocol`
    self.username = username
    self.passwordReference = passwordReference
    self.authenticationRequired = authenticationRequired
    self.prefererHttpTunneling = prefererHttpTunneling
    self.overTls = overTls
    self.overWebSocket = overWebSocket
    self.webSocketPath = webSocketPath
    self.skipCertificateVerification = skipCertificateVerification
    self.sni = sni
    self.certificatePinning = certificatePinning
    self.algorithm = algorithm
  }

  public init(from decoder: Decoder) throws {
    typealias ProxyProtocol = Proxy.`Protocol`

    let container = try decoder.container(keyedBy: CodingKeys.self)
    self.serverAddress = try container.decode(String.self, forKey: .serverAddress)
    self.port = try container.decode(Int.self, forKey: .port)
    self.protocol = try container.decode(ProxyProtocol.self, forKey: .protocol)
    self.username = try container.decodeIfPresent(String.self, forKey: .username) ?? ""
    self.passwordReference =
      try container.decodeIfPresent(String.self, forKey: .passwordReference) ?? ""
    self.authenticationRequired =
      try container.decodeIfPresent(Bool.self, forKey: .authenticationRequired) ?? false
    self.prefererHttpTunneling =
      try container.decodeIfPresent(Bool.self, forKey: .prefererHttpTunneling) ?? false
    self.overTls = try container.decodeIfPresent(Bool.self, forKey: .overTls) ?? false
    self.overWebSocket = try container.decodeIfPresent(Bool.self, forKey: .overWebSocket) ?? false
    self.webSocketPath = try container.decodeIfPresent(String.self, forKey: .webSocketPath) ?? ""
    self.skipCertificateVerification =
      try container.decodeIfPresent(Bool.self, forKey: .skipCertificateVerification) ?? false
    self.sni = try container.decodeIfPresent(String.self, forKey: .sni) ?? ""
    self.certificatePinning =
      try container.decodeIfPresent(String.self, forKey: .certificatePinning) ?? ""
    self.algorithm = try container.decodeIfPresent(Algorithm.self, forKey: .algorithm) ?? .aes128Gcm
  }

  enum CodingKeys: CodingKey {
    case serverAddress
    case port
    case `protocol`
    case username
    case passwordReference
    case authenticationRequired
    case prefererHttpTunneling
    case overTls
    case overWebSocket
    case webSocketPath
    case skipCertificateVerification
    case sni
    case certificatePinning
    case algorithm
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(self.serverAddress, forKey: .serverAddress)
    try container.encode(self.port, forKey: .port)
    try container.encode(self.protocol, forKey: .protocol)
    try container.encodeIfPresent(self.username.isEmpty ? nil : self.username, forKey: .username)
    try container.encodeIfPresent(
      self.passwordReference.isEmpty ? nil : self.passwordReference,
      forKey: .passwordReference
    )
    try container.encodeIfPresent(
      self.authenticationRequired ? true : nil,
      forKey: .authenticationRequired
    )
    try container.encodeIfPresent(
      self.prefererHttpTunneling ? true : nil,
      forKey: .prefererHttpTunneling
    )
    try container.encodeIfPresent(self.overTls ? true : nil, forKey: .overTls)
    try container.encodeIfPresent(self.overWebSocket ? true : nil, forKey: .overWebSocket)
    try container.encodeIfPresent(
      self.webSocketPath.isEmpty ? nil : self.webSocketPath,
      forKey: .webSocketPath
    )
    try container.encodeIfPresent(
      self.skipCertificateVerification ? true : nil,
      forKey: .skipCertificateVerification
    )
    try container.encodeIfPresent(self.sni.isEmpty ? nil : self.sni, forKey: .sni)
    try container.encodeIfPresent(
      self.certificatePinning.isEmpty ? nil : self.certificatePinning,
      forKey: .certificatePinning
    )
    try container.encodeIfPresent(
      self.algorithm == .aes128Gcm ? nil : self.algorithm,
      forKey: .algorithm
    )
  }
}

extension Algorithm: Codable {}
