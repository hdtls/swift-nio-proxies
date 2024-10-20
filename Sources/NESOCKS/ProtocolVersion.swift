//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2021 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

/// `ProtocolVersion` defines SOCKS protocol version.
struct ProtocolVersion: Hashable, RawRepresentable {

  var rawValue: UInt8
}

extension ProtocolVersion {

  /// SOCKS5.
  static let v5 = ProtocolVersion.init(rawValue: 0x05)
}
