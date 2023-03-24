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

import NEMisc
import NIOCore

extension ByteBuffer {

  @discardableResult
  mutating func writeAddress(_ address: NetAddress) -> Int {
    switch address {
    case .domainPort(let domain, let port):
      return writeInteger(UInt16(port))
        + writeInteger(UInt8(2))
        + writeInteger(UInt8(domain.utf8.count))
        + writeString(domain)
    case .socketAddress(.v4(let addr)):
      return writeInteger(addr.address.sin_port.bigEndian)
        + writeInteger(UInt8(1))
        + withUnsafeBytes(of: addr.address.sin_addr) { ptr in
          writeBytes(ptr)
        }
    case .socketAddress(.v6(let addr)):
      return writeInteger(addr.address.sin6_port.bigEndian)
        + writeInteger(UInt8(3))
        + withUnsafeBytes(of: addr.address.sin6_addr) { ptr in
          writeBytes(ptr)
        }
    case .socketAddress(.unixDomainSocket):
      // enforced in the channel initalisers.
      fatalError("UNIX domain sockets are not supported")
    }
  }
}
