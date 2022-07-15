//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2021 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

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

/// The SOCKS Server's response to the client's request
/// indicating if the request succeeded or failed.
struct Response: Hashable {

    /// The SOCKS protocol version - we currently only support v5.
    let version: ProtocolVersion = .v5

    /// The status of the connection - used to check if the request
    /// succeeded or failed.
    var reply: Response.Reply

    /// The host address.
    var boundAddress: NetAddress

    /// Creates a new `Response`.
    /// - parameter reply: The status of the connection - used to check if the request
    /// succeeded or failed.
    /// - parameter boundAddress: The host address.
    init(reply: Response.Reply, boundAddress: NetAddress) {
        self.reply = reply
        self.boundAddress = boundAddress
    }
}

extension Response {
    /// Used to indicate if the SOCKS client's connection request succeeded
    /// or failed.
    struct Reply: Hashable, RawRepresentable {

        /// The connection succeeded and data can now be transmitted.
        static let succeeded = Response.Reply(rawValue: 0x00)

        /// The SOCKS server encountered an internal failure.
        static let generalSOCKSServerFailure = Response.Reply(rawValue: 0x01)

        /// The connection to the host was not allowed.
        static let notAllowed = Response.Reply(rawValue: 0x02)

        /// The host network is not reachable.
        static let networkUnreachable = Response.Reply(rawValue: 0x03)

        /// The target host was not reachable.
        static let hostUnreachable = Response.Reply(rawValue: 0x04)

        /// The connection tot he host was refused
        static let refused = Response.Reply(rawValue: 0x05)

        /// The host address's TTL has expired.
        static let ttlExpired = Response.Reply(rawValue: 0x06)

        /// The provided command is not supported.
        static let commandUnsupported = Response.Reply(rawValue: 0x07)

        /// The provided address type is not supported.
        static let addressTypeUnsupported = Response.Reply(rawValue: 0x08)

        /// The raw `UInt8` status code.
        var rawValue: UInt8

        /// Creates a new `Reply` from the given raw status code. Common
        /// statuses have convenience variables.
        /// - parameter value: The raw `UInt8` code sent by the SOCKS server.
        init(rawValue: UInt8) {
            self.rawValue = rawValue
        }
    }
}
