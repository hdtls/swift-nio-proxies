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

import NIO

// MARK: - ClientRequest

/// Instructs the SOCKS proxy server of the target host,
/// and how to connect.
public struct Request: Hashable {
    
    /// The SOCKS protocol version - we currently only support v5.
    public let version: SOCKSProtocolVersion = .v5
    
    /// How to connect to the host.
    public var command: Command
    
    /// The target host address.
    public var address: NetAddress
    
    /// Creates a new `Request`.
    /// - parameter command: How to connect to the host.
    /// - parameter address: The target host address.
    public init(command: Command, address: NetAddress) {
        self.command = command
        self.address = address
    }
    
}

extension ByteBuffer {
    
    @discardableResult mutating func writeClientRequest(_ request: Request) -> Int {
        var written = writeInteger(request.version.rawValue)
        written += writeInteger(request.command.value)
        written += writeInteger(UInt8(0))
        written += applying(request.address)
        return written
    }
    
    @discardableResult mutating func readClientRequestIfPossible() throws -> Request? {
        return try parseUnwindingIfNeeded { buffer -> Request? in
            guard
                try buffer.readAndValidateProtocolVersion() != nil,
                let command = buffer.readInteger(as: UInt8.self),
                try buffer.readAndValidateReserved() != nil,
                let address = try buffer.readAddressIfPossible()
            else {
                return nil
            }
            return .init(command: .init(value: command), address: address)
        }
    }
    
}

// MARK: - Command

/// What type of connection the SOCKS server should establish with
/// the target host.
public struct Command: Hashable {
    
    /// Typically the primary connection type, suitable for HTTP.
    public static let connect = Command(value: 0x01)
    
    /// Used in protocols that require the client to accept connections
    /// from the server, e.g. FTP.
    public static let bind = Command(value: 0x02)
    
    /// Used to establish an association within the UDP relay process to
    /// handle UDP datagrams.
    public static let udpAssociate = Command(value: 0x03)
    
    public var value: UInt8
    
    public init(value: UInt8) {
        self.value = value
    }
}
