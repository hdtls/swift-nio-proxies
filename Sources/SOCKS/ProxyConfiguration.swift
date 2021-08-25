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

import enum NIO.SocketAddress

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

    /// Returns a base64 encoded basic authentication credential as an authorization header tuple.
    ///
    /// - parameter user:     The user.
    /// - parameter password: The password.
    ///
    /// - returns: A tuple with Authorization header and credential value if encoding succeeds, `nil` otherwise.
    public var authorizationHeader: (key: String, value: String)? {
        guard let data = "\(username):\(password)".data(using: .utf8) else { return nil }

        let credential = data.base64EncodedString(options: [])

        return (key: "Authorization", value: "Basic \(credential)")
    }
}

/// SOCKS Proxy configuation
public struct ProxyConfiguration {
    /// Basic authentication info.
    public var basicAuthorization: BasicAuthorization?

    /// TLS SNI value
    public var customTLSSNI: String?

    /// A bool value to determise whether proxy should skip server
    /// certificate verification.
    public var skipServerCertificateVerification: Bool = false

    public var baseAddress: SocketAddress
    
    public init(basicAuthorization: BasicAuthorization? = nil,
                customTLSSNI: String? = nil,
                skipServerCertificateVerification: Bool = false,
                baseAddress: SocketAddress) {
        self.basicAuthorization = basicAuthorization
        self.customTLSSNI = customTLSSNI
        self.skipServerCertificateVerification = skipServerCertificateVerification
        self.baseAddress = baseAddress
    }
}
