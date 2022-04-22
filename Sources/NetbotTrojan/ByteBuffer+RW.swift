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

import NIOCore
import NetbotCore

// TODO: Duplicated with SOCKS5
extension ByteBuffer {

    /// Read `NetAddress` from buffer.
    /// - Returns: If success return `NetAddress` else return nil for need more bytes.
    mutating func readAddressIfPossible() throws -> NetAddress? {
        var buffer = self
        defer {
            self = buffer
        }

        guard let rawValue = buffer.readInteger(as: UInt8.self) else {
            return nil
        }

        switch rawValue {
            case 0x03:
                guard let length = buffer.readInteger(as: UInt8.self),
                    let host = buffer.readString(length: Int(length)),
                    let port = buffer.readInteger(as: UInt16.self)
                else {
                    return nil
                }
                return .domainPort(host, Int(port))
            case 0x01, 0x04:
                guard let packedIPAddress = buffer.readSlice(length: rawValue == 1 ? 4 : 16),
                    let port = buffer.readInteger(as: UInt16.self)
                else {
                    return nil
                }
                return .socketAddress(try .init(packedIPAddress: packedIPAddress, port: Int(port)))
            default:
                assertionFailure("Illegal address type \(rawValue).")
                return nil
        }
    }

    /// Apply `NetAddress` to `ByteBuffer`.
    /// - Parameter address: The address waiting to write.
    /// - Returns: Byte count.
    @discardableResult
    mutating func writeAddress(_ address: NetAddress) -> Int {
        switch address {
            case .socketAddress(.v4(let address)):
                return writeInteger(UInt8(1))
                    + withUnsafeBytes(of: address.address.sin_addr) { ptr in
                        writeBytes(ptr)
                    }
                    + writeInteger(address.address.sin_port.bigEndian)
            case .socketAddress(.v6(let address)):
                return writeInteger(UInt8(4))
                    + withUnsafeBytes(of: address.address.sin6_addr) { ptr in
                        writeBytes(ptr)
                    }
                    + writeInteger(address.address.sin6_port.bigEndian)
            case .socketAddress(.unixDomainSocket):
                // enforced in the channel initalisers.
                fatalError("UNIX domain sockets are not supported")
            case .domainPort(let domain, let port):
                return writeInteger(UInt8(0x03))
                    + writeInteger(UInt8(domain.utf8.count))
                    + writeString(domain)
                    + writeInteger(UInt16(port))
        }
    }
}
