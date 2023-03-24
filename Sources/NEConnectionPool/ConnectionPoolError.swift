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

/// Errors thrown by `ConnectionPool`.
public enum ConnectionPoolError: Error {
  /// The connection pool has shutdown.
  case shutdown
}

public enum ConnectionPoolTimeoutError: Error {
  /// The connection request timed out.
  case connectionRequestTimeout
}
