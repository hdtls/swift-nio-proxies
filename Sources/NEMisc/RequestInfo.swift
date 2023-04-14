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

import Foundation
@_exported import NIOCore

/// Represents an proxy request in an application.
public struct RequestInfo: Equatable, Hashable, Sendable {

  /// The address of the receiver.
  public var address: NetAddress

  /// This data is sent as the message body of the request.
  public var body: ByteBuffer?

  public init(address: NetAddress) {
    self.address = address
  }
}
