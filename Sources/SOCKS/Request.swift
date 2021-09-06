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
    public var address: SOCKSAddress
    
    /// Creates a new `Request`.
    /// - parameter command: How to connect to the host.
    /// - parameter address: The target host address.
    public init(command: Command, address: SOCKSAddress) {
        self.command = command
        self.address = address
    }
    
}

extension ByteBuffer {
    
    @discardableResult mutating func writeClientRequest(_ request: Request) -> Int {
        var written = writeInteger(request.version.rawValue)
        written += writeInteger(request.command.value)
        written += writeInteger(UInt8(0))
        written += writeAddress(request.address)
        return written
    }
    
    @discardableResult mutating func readClientRequest() throws -> Request? {
        return try parseUnwindingIfNeeded { buffer -> Request? in
            guard
                try buffer.readAndValidateProtocolVersion() != nil,
                let command = buffer.readInteger(as: UInt8.self),
                try buffer.readAndValidateReserved() != nil,
                let address = try buffer.readAddress()
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

// MARK: - SOCKSAddress

/// The address used to connect to the target host.
public enum SOCKSAddress: Hashable {
    
    case address(SocketAddress)
    
    case domain(String, port: Int)
    
    static let ipv4IdentifierByte: UInt8 = 0x01
    static let domainIdentifierByte: UInt8 = 0x03
    static let ipv6IdentifierByte: UInt8 = 0x04
    
    /// How many bytes are needed to represent the address, excluding the port
    var size: Int {
        switch self {
        case .address(.v4):
            return 4
        case .address(.v6):
            return 16
        case .address(.unixDomainSocket):
            fatalError("Unsupported")
        case .domain(let domain, port: _):
            // the +1 is for the leading "count" byte
            // containing how many UTF8 bytes are in the
            // domain
            return domain.utf8.count + 1
        }
    }
}

extension ByteBuffer {
    
    mutating func readAddress() throws -> SOCKSAddress? {
        return try parseUnwindingIfNeeded { buffer in
            guard let type = buffer.readInteger(as: UInt8.self) else {
                return nil
            }
            
            switch type {
            case SOCKSAddress.ipv4IdentifierByte:
                return try buffer.readIPv4Address()
            case SOCKSAddress.domainIdentifierByte:
                return buffer.readDomain()
            case SOCKSAddress.ipv6IdentifierByte:
                return try buffer.readIPv6Address()
            default:
                throw SOCKSError.invalidAddressType(actual: type)
            }
        }
    }
    
    mutating func readIPv4Address() throws -> SOCKSAddress? {
        return try parseUnwindingIfNeeded { buffer in
            guard
                let bytes = buffer.readSlice(length: 4),
                let port = buffer.readPort()
            else {
                return nil
            }
            return .address(try .init(packedIPAddress: bytes, port: port))
        }
    }
    
    mutating func readIPv6Address() throws -> SOCKSAddress? {
        return try parseUnwindingIfNeeded { buffer in
            guard
                let bytes = buffer.readSlice(length: 16),
                let port = buffer.readPort()
            else {
                return nil
            }
            return .address(try .init(packedIPAddress: bytes, port: port))
        }
    }
    
    mutating func readDomain() -> SOCKSAddress? {
        return parseUnwindingIfNeeded { buffer in
            guard
                let length = buffer.readInteger(as: UInt8.self),
                let host = buffer.readString(length: Int(length)),
                let port = buffer.readPort()
            else {
                return nil
            }
            return .domain(host, port: port)
        }
    }
    
    mutating func readPort() -> Int? {
        guard let port = readInteger(as: UInt16.self) else {
            return nil
        }
        return Int(port)
    }
    
    @discardableResult
    mutating func writeAddress(_ type: SOCKSAddress) -> Int {
        switch type {
        case .address(.v4(let address)):
            return writeInteger(SOCKSAddress.ipv4IdentifierByte)
                + writeIPv4Address(address.address)
                + writeInteger(UInt16(bigEndian: address.address.sin_port))
        case .address(.v6(let address)):
            return writeInteger(SOCKSAddress.ipv6IdentifierByte)
                + writeIPv6Address(address.address)
                + writeInteger(UInt16(bigEndian: address.address.sin6_port))
        case .address(.unixDomainSocket):
            // enforced in the channel initalisers.
            fatalError("UNIX domain sockets are not supported")
        case .domain(let domain, port: let port):
            return writeInteger(SOCKSAddress.domainIdentifierByte)
                + writeInteger(UInt8(domain.utf8.count))
                + writeString(domain)
                + writeInteger(UInt16(port))
        }
    }
    
    @discardableResult
    mutating func writeIPv6Address(_ addr: sockaddr_in6) -> Int {
        return withUnsafeBytes(of: addr.sin6_addr) { pointer in
            return writeBytes(pointer)
        }
    }
    
    @discardableResult
    mutating func writeIPv4Address(_ addr: sockaddr_in) -> Int {
        return withUnsafeBytes(of: addr.sin_addr) { pointer in
            return writeBytes(pointer)
        }
    }
}
