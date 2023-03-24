//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2021 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NEMisc

/// Instructs the SOCKS proxy server of the target host,
/// and how to connect.
struct Request: Hashable {

  /// The SOCKS protocol version - we currently only support v5.
  let version: ProtocolVersion

  /// How to connect to the host.
  let command: Command

  let reserved: UInt8

  /// The target host address.
  let address: NetAddress

  /// Initialize an instance of `Request` with specified version command and address.
  ///
  /// - note: Only SOCKS Protocol V5 is supported.
  init(
    version: ProtocolVersion = .v5,
    command: Command,
    reserved: UInt8 = 0,
    address: NetAddress
  ) {
    self.version = version
    self.command = command
    self.reserved = reserved
    self.address = address
  }
}

/// What type of connection the SOCKS server should establish with
/// the target host.
struct Command: Hashable, RawRepresentable {

  /// Typically the primary connection type, suitable for HTTP.
  static let connect = Command(rawValue: 0x01)

  /// Used in protocols that require the client to accept connections
  /// from the server, e.g. FTP.
  static let bind = Command(rawValue: 0x02)

  /// Used to establish an association within the UDP relay process to
  /// handle UDP datagrams.
  static let udpAssociate = Command(rawValue: 0x03)

  var rawValue: UInt8
}
