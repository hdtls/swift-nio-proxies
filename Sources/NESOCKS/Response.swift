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

/// The SOCKS Server's response to the client's request
/// indicating if the request succeeded or failed.
struct Response: Hashable {

  /// The SOCKS protocol version - we currently only support v5.
  let version: ProtocolVersion

  /// The status of the connection - used to check if the request
  /// succeeded or failed.
  let reply: Response.Reply

  let reserved: UInt8

  /// The host address.
  let boundAddress: NetAddress

  /// Initialize an instance of `Response`.
  /// - Parameters:
  ///   - version: The socks protocol version.
  ///   - reply: The status of the connection - used to check if the request succeeded or failed.
  ///   - boundAddress: The host address.
  init(
    version: ProtocolVersion = .v5,
    reply: Response.Reply,
    reserved: UInt8 = 0,
    boundAddress: NetAddress
  ) {
    self.version = version
    self.reply = reply
    self.reserved = reserved
    self.boundAddress = boundAddress
  }
}

extension Response {
  /// Used to indicate if the SOCKS client's connection request succeeded
  /// or failed.
  struct Reply: Hashable, RawRepresentable {

    /// The connection succeeded and data can now be transmitted.
    static let succeeded = Response.Reply(rawValue: 0x00)

    /// The SOCKS server encountered an internal failure.
    static let generalSOCKSServerFailure = Response.Reply(rawValue: 0x01)

    /// The connection to the host was not allowed.
    static let notAllowed = Response.Reply(rawValue: 0x02)

    /// The host network is not reachable.
    static let networkUnreachable = Response.Reply(rawValue: 0x03)

    /// The target host was not reachable.
    static let hostUnreachable = Response.Reply(rawValue: 0x04)

    /// The connection tot he host was refused
    static let refused = Response.Reply(rawValue: 0x05)

    /// The host address's TTL has expired.
    static let ttlExpired = Response.Reply(rawValue: 0x06)

    /// The provided command is not supported.
    static let commandUnsupported = Response.Reply(rawValue: 0x07)

    /// The provided address type is not supported.
    static let addressTypeUnsupported = Response.Reply(rawValue: 0x08)

    /// The raw `UInt8` status code.
    var rawValue: UInt8
  }
}
