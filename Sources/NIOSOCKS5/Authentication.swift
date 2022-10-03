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

enum Authentication {

    /// The SOCKS authentication method to use, defined in RFC 1928.
    struct Method: Equatable, RawRepresentable {
        /// No authentication required
        static let noRequired = Method(rawValue: 0x00)

        /// Use GSSAPI
        static let gssapi = Method(rawValue: 0x01)

        /// Username / password authentication
        static let usernamePassword = Method(rawValue: 0x02)

        /// No acceptable authentication methods
        static let noAcceptable = Method(rawValue: 0xFF)

        /// The method identifier, valid values are in the range 0:255.
        public var rawValue: UInt8

        public init(rawValue: UInt8) {
            self.rawValue = rawValue
        }
    }

    /// The SOCKS V5 Username/Password Authentication request, defined in RFC 1929.
    struct UsernameAuthenticationRequest {

        /// The VER field contains the current version of the subnegotiation, which is X'01'.
        let version: UInt8

        /// The UNAME field contains the username as known to the source operating system.
        let username: String

        /// The PASSWD field contains the password association with the given UNAME.
        let password: String

        /// Create a new `Authentication.UsernameAuthenticationRequest`
        /// - Parameters:
        ///   - version: The authentication subnegotiation version
        ///   - username: The authentication username
        ///   - password: The authentication password
        init(version: UInt8 = 1, username: String, password: String) {
            self.version = version
            self.username = username
            self.password = password
        }
    }

    /// The SOCKS V5 Username/Password Authentication response.
    struct UsernameAuthenticationResponse {

        /// The version of the subnegotiation
        let version: UInt8

        /// The status of authentication
        /// A STATUS field of X'00' indicates success.
        /// If the server returns a `failure' (STATUS value other than X'00') status,
        /// it MUST close the connection.
        let status: UInt8

        var isSuccess: Bool {
            return status == 0
        }

        /// Initialize an instance of `UsernameAuthenticationResponse` with specified version and status.
        ///
        /// The VER field contains the current version of the subnegotiation, which is X'01'.
        ///
        /// - Parameters:
        ///   - version: The current version of the SOCKS V5 Username/Password authentication subnegotiation.
        ///   - status: The response status. zero if success otherwise failed.
        init(version: UInt8 = 1, status: UInt8) {
            self.version = version
            self.status = status
        }
    }
}

extension Authentication.Method {

    /// Clients begin the SOCKS handshake process
    /// by providing an array of suggested authentication
    /// methods.
    struct Request {
        /// The protocol version.
        let version: ProtocolVersion

        /// The client-supported authentication methods.
        /// The SOCKS server will select one to use.
        var methods: [Authentication.Method]

        /// Creates a new `ClientGreeting`
        /// - parameter methods: The client-supported authentication methods.
        init(version: ProtocolVersion = .v5, methods: [Authentication.Method]) {
            self.version = version
            self.methods = methods
        }
    }

    /// Used by the SOCKS server to inform the client which
    /// authentication method it would like to use out of those
    /// offered.
    struct Response {
        /// The SOCKS protocol version - we currently only support v5.
        let version: ProtocolVersion

        /// The server's selected authentication method.
        var method: Authentication.Method

        /// Creates a new `MethodSelection` wrapping an `Authentication.Method`.
        /// - parameter method: The selected `Authentication.Method`.
        init(version: ProtocolVersion = .v5, method: Authentication.Method) {
            self.version = version
            self.method = method
        }
    }
}

#if swift(>=5.5) && canImport(_Concurrency)
extension Authentication.Method: Sendable {}

extension Authentication.UsernameAuthenticationRequest: Sendable {}

extension Authentication.UsernameAuthenticationResponse: Sendable {}

extension Authentication.Method.Request: Sendable {}

extension Authentication.Method.Response: Sendable {}
#endif
