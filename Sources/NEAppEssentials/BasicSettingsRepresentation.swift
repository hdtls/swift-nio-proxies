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
public protocol BasicSettingsRepresentation: Hashable, Sendable {

  /// Log level use for `Logging.Logger`.`
  var logLevel: Logger.Level { get }

  /// DNS servers use for system proxy.
  var dnsServers: [String] { get }

  /// Exceptions use for system proxy.
  var exceptions: [String] { get }

  /// Http listen address use for system http proxy.
  var httpListenAddress: String? { get }

  /// Http listen port use for system http proxy
  var httpListenPort: Int? { get }

  /// Socks listen address use for system socks proxy.
  var socksListenAddress: String? { get }

  /// Socks listen port use for system socks proxy.
  var socksListenPort: Int? { get }

  /// A boolean value that determines whether system proxy should exclude simple hostnames.
  var excludeSimpleHostnames: Bool { get }
}
