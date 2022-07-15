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

/// Instructs the SOCKS proxy server of the target host,
/// and how to connect.
struct Request: Hashable {

    /// The SOCKS protocol version - we currently only support v5.
    let version: ProtocolVersion = .v5

    /// How to connect to the host.
    var command: Command

    /// The target host address.
    var address: NetAddress

    /// Creates a new `Request`.
    /// - parameter command: How to connect to the host.
    /// - parameter address: The target host address.
    init(command: Command, address: NetAddress) {
        self.command = command
        self.address = address
    }
}

/// What type of connection the SOCKS server should establish with
/// the target host.
struct Command: Hashable, RawRepresentable {

    /// Typically the primary connection type, suitable for HTTP.
    static let connect = Command(rawValue: 0x01)

    /// Used in protocols that require the client to accept connections
    /// from the server, e.g. FTP.
    static let bind = Command(rawValue: 0x02)

    /// Used to establish an association within the UDP relay process to
    /// handle UDP datagrams.
    static let udpAssociate = Command(rawValue: 0x03)

    var rawValue: UInt8

    init(rawValue: UInt8) {
        self.rawValue = rawValue
    }
}
