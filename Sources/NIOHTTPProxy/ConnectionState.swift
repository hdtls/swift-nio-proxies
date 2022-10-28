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

import Foundation

/// The state of the HTTP connection.
enum ConnectionState: Equatable {
    /// Nothing is active on this connection, the next message we expect would be a request `.head`.
    case idle

    /// We are evaluating request or response message.
    case handshaking

    /// After evaluating finished, tunnel become active.
    case active

    /// Error
    case failed
}
