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

/// Basic settings object that defines behavior and polices for logging and proxy settings.
public struct BasicSettings: Sendable {

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

  /// Initialize an instance of `BasicSettings`.
  ///
  /// Calling this method is equivalent to calling `init(logLevel:dnsServers:exceptions:httpListenAddress:httpListenPort:socksListenAddress:socksListenPort:excludeSimpleHostnames:)`
  /// with `info` logLevel, `[]` dnsServers, `nil` exceptions, httpListenAddress, httpListenPort,
  /// socksListenAddress, socksListenPort and `false` excludeSimpleHostnames.
  public init() {
    self.init(
      logLevel: .info,
      dnsServers: [],
      exceptions: [],
      httpListenAddress: nil,
      httpListenPort: nil,
      socksListenAddress: nil,
      socksListenPort: nil,
      excludeSimpleHostnames: false
    )
  }
}
