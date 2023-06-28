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

enum Proxy {
  /// Proxy protocol definition.
  enum `Protocol`: Sendable, CustomStringConvertible {
    case http
    case socks5

    var description: String {
      switch self {
      case .http: return "HTTP"
      case .socks5: return "SOCKS5"
      }
    }
  }
}
