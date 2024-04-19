//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2024 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation
import NIOCore
import _NELinux

extension IPv4Address {
  /// Create an `IPv4Address` object from a `sockaddr_in`.
  internal init(_ sockAddr: sockaddr_in) {
    var localAddr = sockAddr
    self = withUnsafeBytes(of: &localAddr.sin_addr) {
      precondition($0.count == 4)
      let addrData = Data(bytes: $0.baseAddress!, count: $0.count)
      return IPv4Address(addrData)!
    }
  }
}

extension IPv6Address {
  internal init(_ sockAddr: sockaddr_in6) {
    var localAddr = sockAddr
    self = withUnsafeBytes(of: &localAddr.sin6_addr) {
      precondition($0.count == 16)
      let addrData = Data(bytes: $0.baseAddress!, count: $0.count)
      return IPv6Address(addrData)!
    }
  }
}

extension NWEndpoint {
  internal init(_ socketAddress: SocketAddress) {
    switch socketAddress {
    case .unixDomainSocket(let uds):
      var address = uds.address
      let path: String = withUnsafeBytes(of: &address.sun_path) { ptr in
        let ptr = ptr.baseAddress!.bindMemory(to: UInt8.self, capacity: 104)
        return String(cString: ptr)
      }
      self = NWEndpoint.unix(path: path)
    case .v4(let v4Addr):
      let v4Address = IPv4Address(v4Addr.address)
      let port = NWEndpoint.Port(rawValue: UInt16(socketAddress.port!))!
      self = NWEndpoint.hostPort(host: .ipv4(v4Address), port: port)
    case .v6(let v6Addr):
      let v6Address = IPv6Address(v6Addr.address)
      let port = NWEndpoint.Port(rawValue: UInt16(socketAddress.port!))!
      self = NWEndpoint.hostPort(host: .ipv6(v6Address), port: port)
    }
  }
}
