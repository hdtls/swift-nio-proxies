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

@_exported import NESS

/// A wrapper object use to decoding and encoding proxy settings.
public struct Proxy: Sendable {

  /// Proxy protocol definition.
  public enum `Protocol`: String, CaseIterable, CustomStringConvertible, Sendable {
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
  public var password: String = ""

  /// Password field for this proxy settings. For now just return password instead.
  public var passwordReference: String { password }

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
    password: String = "",
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
    self.password = password
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
}
