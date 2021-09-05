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
@_exported import NIOCore

/// Represent a socket address or domain port to which we may want to connect or bind.
public enum NetAddress: Equatable, Hashable {
    case domainPort(String, Int)
    case socketAddress(SocketAddress)
}

/// Special `Error` that may be thrown if we fail to create a `SocketAddress`.
public enum NetAddressError: Error, Equatable {
    case invalidAddressType(actual: UInt8)
}

/// SOCKS address type defined in RFC 1928.
fileprivate enum __SOCKSAddrID: UInt8, CaseIterable {
    /// IP V4 address: X'01'
    case v4 = 0x01
    
    /// DOMAINNAME: X'03'
    case domain = 0x03
    
    /// IP V6 address
    case v6 = 0x04
}

extension ByteBuffer {
    
    /// Read `NetAddress` from buffer.
    /// - Throws: May throw  `NetAddressError.invalidAddressType` if address type is illegal.
    /// - Returns: If success return `NetAddress` else return nil for need more bytes.
    public mutating func readNetAddress() throws -> NetAddress? {
        return try parseUnwindingIfNeeded { buffer in
            guard let rawValue = buffer.readInteger(as: UInt8.self) else {
                return nil
            }
            
            guard let type = __SOCKSAddrID(rawValue: rawValue) else {
                throw NetAddressError.invalidAddressType(actual: rawValue)
            }
            
            // Unlike IPv4 and IPv6 address domain name have a variable length
            if case .domain = type {
                guard let length = buffer.readInteger(as: UInt8.self),
                      let host = buffer.readString(length: Int(length)),
                      let port = buffer.readInteger(as: in_port_t.self) else {
                          return nil
                      }
                return .domainPort(host, Int(port))
            }
            
            guard let packedIPAddress = buffer.readSlice(length: type == .v4 ? 4 : 16),
                  let port = buffer.readInteger(as: in_port_t.self) else {
                      return nil
                  }
            return .socketAddress(try! .init(packedIPAddress: packedIPAddress, port: Int(port)))
        }
    }
    
    
    /// Apply `NetAddress` to `ByteBuffer`.
    /// - Parameter address: The address waiting to write.
    /// - Returns: Byte count.
    @discardableResult
    public mutating func applying(_ address: NetAddress) -> Int {
        switch address {
            case .socketAddress(.v4(let address)):
                return writeInteger(__SOCKSAddrID.v4.rawValue)
                + withUnsafeBytes(of: address.address.sin_addr) { pointer in
                    writeBytes(pointer)
                }
                + writeInteger(address.address.sin_port.bigEndian)
            case .socketAddress(.v6(let address)):
                return writeInteger(__SOCKSAddrID.v6.rawValue)
                + withUnsafeBytes(of: address.address.sin6_addr) { pointer in
                    writeBytes(pointer)
                }
                + writeInteger(address.address.sin6_port.bigEndian)
            case .socketAddress(.unixDomainSocket):
                // enforced in the channel initalisers.
                fatalError("UNIX domain sockets are not supported")
            case .domainPort(let domain, let port):
                return writeInteger(__SOCKSAddrID.domain.rawValue)
                + writeInteger(UInt8(domain.utf8.count))
                + writeString(domain)
                + writeInteger(in_port_t(port))
        }
    }
}

extension Data {
    
    /// Read `NetAddress` from buffer.
    /// - Throws: May throw  `NetAddressError.invalidAddressType` if address type is illegal.
    /// - Returns: If success return `NetAddress` else return nil for need more bytes.
    public mutating func readNetAddress() throws -> NetAddress? {
        let data = self
        var byteBuffer = ByteBuffer(bytes: data)
        defer {
            self = Data(byteBuffer.readBytes(length: byteBuffer.readableBytes)!)
        }
        return try byteBuffer.readNetAddress()
    }
    
    /// Apply `NetAddress` to `ByteBuffer`.
    /// - Parameter address: The address waiting to write.
    /// - Returns: Byte count.
    @discardableResult
    public mutating func applying(_ address: NetAddress) -> Int {
        var byteBuffer = ByteBuffer()
        defer {
            append(contentsOf: byteBuffer.readBytes(length: byteBuffer.readableBytes)!)
        }
        return byteBuffer.applying(address)
    }
}
