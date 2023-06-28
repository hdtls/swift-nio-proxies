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

import Logging
import NEAppEssentials

/// Basic settings object that defines behavior and polices for logging and proxy settings.
public struct BasicSettings: BasicSettingsRepresentation, Codable, Hashable, Sendable {

  /// Log level use for `Logging.Logger`.`
  public var logLevel: Logger.Level = .info

  /// DNS servers use for system proxy.
  public var dnsServers: [String] = []

  /// Exceptions use for system proxy.
  public var exceptions: [String] = []

  /// Http listen address use for system http proxy.
  public var httpListenAddress: String?

  /// Http listen port use for system http proxy
  public var httpListenPort: Int?

  /// Socks listen address use for system socks proxy.
  public var socksListenAddress: String?

  /// Socks listen port use for system socks proxy.
  public var socksListenPort: Int?

  /// A boolean value that determines whether system proxy should exclude simple hostnames.
  public var excludeSimpleHostnames: Bool = false

  /// Initialize an instance of `BasicSettings` with specified logLevel, dnsServers exceptions,
  /// httpListenAddress, httpListenPort, socksListenAddress, socksListenPort and excludeSimpleHostnames.
  public init(
    logLevel: Logger.Level,
    dnsServers: [String],
    exceptions: [String],
    httpListenAddress: String?,
    httpListenPort: Int?,
    socksListenAddress: String?,
    socksListenPort: Int?,
    excludeSimpleHostnames: Bool
  ) {
    self.logLevel = logLevel
    self.dnsServers = dnsServers
    self.exceptions = exceptions
    self.httpListenAddress = httpListenAddress
    self.httpListenPort = httpListenPort
    self.socksListenAddress = socksListenAddress
    self.socksListenPort = socksListenPort
    self.excludeSimpleHostnames = excludeSimpleHostnames
  }

  /// Initialize an instance of `BasicSettings` with default values.
  public init() {

  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    self.logLevel = try container.decodeIfPresent(Logger.Level.self, forKey: .logLevel) ?? .info
    self.dnsServers = try container.decodeIfPresent([String].self, forKey: .dnsServers) ?? []
    self.exceptions = try container.decodeIfPresent([String].self, forKey: .exceptions) ?? []
    self.httpListenAddress = try container.decodeIfPresent(String.self, forKey: .httpListenAddress)
    self.httpListenPort = try container.decodeIfPresent(Int.self, forKey: .httpListenPort)
    self.socksListenAddress = try container.decodeIfPresent(
      String.self,
      forKey: .socksListenAddress
    )
    self.socksListenPort = try container.decodeIfPresent(Int.self, forKey: .socksListenPort)
    self.excludeSimpleHostnames =
      try container.decodeIfPresent(Bool.self, forKey: .excludeSimpleHostnames) ?? false
  }

  enum CodingKeys: CodingKey {
    case logLevel
    case dnsServers
    case exceptions
    case httpListenAddress
    case httpListenPort
    case socksListenAddress
    case socksListenPort
    case excludeSimpleHostnames
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(self.logLevel, forKey: .logLevel)
    try container.encode(self.dnsServers, forKey: .dnsServers)
    try container.encode(self.exceptions, forKey: .exceptions)
    try container.encodeIfPresent(self.httpListenAddress, forKey: .httpListenAddress)
    try container.encodeIfPresent(self.httpListenPort, forKey: .httpListenPort)
    try container.encodeIfPresent(self.socksListenAddress, forKey: .socksListenAddress)
    try container.encodeIfPresent(self.socksListenPort, forKey: .socksListenPort)
    try container.encode(self.excludeSimpleHostnames, forKey: .excludeSimpleHostnames)
  }
}
