//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2021 Junfeng Zhang. and the Netbot project authors
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
    case evaluating

    /// After evaluating finished, tunnel become active.
    case active

    /// Error
    case failed

    /// Move state into `.evaluating`.
    /// - Throws: HTTPProxyError.invalidServerState if previouse state is not equal to `.idle`.
    mutating func evaluating() throws {
        guard self == .idle else {
            throw HTTPProxyError.invalidServerState
        }
        self = .evaluating
    }

    /// Move state inot `.active`
    /// - Throws: HTTPProxyError.invalidServerState if previouse state is not equal to `.evaluating`.
    mutating func established() throws {
        guard self == .evaluating else {
            throw HTTPProxyError.invalidServerState
        }
        self = .active
    }
}
