//===----------------------------------------------------------------------===//
//
// This source file is part of the swift-nio-Netbot open source project
//
// Copyright © 2019 Netbot Ltd. and the swift-nio-Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIO

/// A basic username and password.
public struct BasicAuthorization: Codable, Equatable {
    /// The username, sometimes an email address
    public let username: String

    /// The plaintext password
    public let password: String

    /// Create a new `BasicAuthorization`.
    public init(username: String, password: String) {
        self.username = username
        self.password = password
    }
}

public struct ProxyConfiguration {

    /// Basic authentication info.
    public var basicAuthorization: BasicAuthorization?

    public var alwaysUseCONNECT: Bool

    public var taskAddress: SocketAddress?

    public init(basicAuthorization: BasicAuthorization? = nil,
                alwaysUseCONNECT: Bool = false,
                taskAddress: SocketAddress? = nil) {
        self.basicAuthorization = basicAuthorization
        self.alwaysUseCONNECT = alwaysUseCONNECT
        self.taskAddress = taskAddress
    }}
