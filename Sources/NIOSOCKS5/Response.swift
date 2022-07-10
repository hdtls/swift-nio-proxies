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
public struct Response: Hashable {

    /// The SOCKS protocol version - we currently only support v5.
    public let version: ProtocolVersion = .v5

    /// The status of the connection - used to check if the request
    /// succeeded or failed.
    public var reply: SOCKSServerReply

    /// The host address.
    public var boundAddress: NetAddress

    /// Creates a new `Response`.
    /// - parameter reply: The status of the connection - used to check if the request
    /// succeeded or failed.
    /// - parameter boundAddress: The host address.
    public init(reply: SOCKSServerReply, boundAddress: NetAddress) {
        self.reply = reply
        self.boundAddress = boundAddress
    }
}

extension ByteBuffer {

    mutating func readServerResponseIfPossible() throws -> Response? {
        return try parseUnwindingIfNeeded { buffer in
            guard
                try buffer.readAndValidateProtocolVersion() != nil,
                let reply = buffer.readInteger(as: UInt8.self).map({ SOCKSServerReply(value: $0) }),
                try buffer.readAndValidateReserved() != nil,
                let boundAddress = try buffer.readAddressIfPossible()
            else {
                return nil
            }
            return .init(reply: reply, boundAddress: boundAddress)
        }
    }

    @discardableResult mutating func writeServerResponse(_ response: Response) -> Int {
        return writeInteger(response.version.rawValue) + writeInteger(response.reply.value)
            + writeInteger(0, as: UInt8.self) + applying(response.boundAddress)
    }

}

/// Used to indicate if the SOCKS client's connection request succeeded
/// or failed.
public struct SOCKSServerReply: Hashable {

    /// The connection succeeded and data can now be transmitted.
    public static let succeeded = SOCKSServerReply(value: 0x00)

    /// The SOCKS server encountered an internal failure.
    public static let generalSOCKSServerFailure = SOCKSServerReply(value: 0x01)

    /// The connection to the host was not allowed.
    public static let notAllowed = SOCKSServerReply(value: 0x02)

    /// The host network is not reachable.
    public static let networkUnreachable = SOCKSServerReply(value: 0x03)

    /// The target host was not reachable.
    public static let hostUnreachable = SOCKSServerReply(value: 0x04)

    /// The connection tot he host was refused
    public static let refused = SOCKSServerReply(value: 0x05)

    /// The host address's TTL has expired.
    public static let ttlExpired = SOCKSServerReply(value: 0x06)

    /// The provided command is not supported.
    public static let commandUnsupported = SOCKSServerReply(value: 0x07)

    /// The provided address type is not supported.
    public static let addressTypeUnsupported = SOCKSServerReply(value: 0x08)

    /// The raw `UInt8` status code.
    public var value: UInt8

    /// Creates a new `Reply` from the given raw status code. Common
    /// statuses have convenience variables.
    /// - parameter value: The raw `UInt8` code sent by the SOCKS server.
    public init(value: UInt8) {
        self.value = value
    }
}
