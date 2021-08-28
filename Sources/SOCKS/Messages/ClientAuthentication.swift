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

import NIO
import Helpers

/// Clients begin the SOCKS handshake process
/// by providing an array of suggested authentication
/// methods.

/// Once the SOCKS V5 server has started, and the client has selected the
/// Username/Password Authentication protocol, the Username/Password
/// subnegotiation begins.  This begins with the client producing a
/// Username/Password request:
///
/// +----+------+----------+------+----------+
/// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
/// +----+------+----------+------+----------+
/// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
/// +----+------+----------+------+----------+
///
/// The VER field contains the current version of the subnegotiation,
/// which is X'01'. The ULEN field contains the length of the UNAME field
/// that follows. The UNAME field contains the username as known to the
/// source operating system. The PLEN field contains the length of the
/// PASSWD field that follows. The PASSWD field contains the password
/// association with the given UNAME.
public struct ClientBasicAuthentication: Hashable {
        
    // The current version of the subnegotiation
    public let version: UInt8
        
    public let username: String
        
    public let password: String
    
    public init(version: UInt8 = 1, username: String, password: String) {
        self.version = version
        self.username = username
        self.password = password
    }
}

/// The server verifies the supplied UNAME and PASSWD, and sends the
/// following response:
///
/// +----+--------+
/// |VER | STATUS |
/// +----+--------+
/// | 1  |   1    |
/// +----+--------+
///
/// A STATUS field of X'00' indicates success. If the server returns a
/// `failure' (STATUS value other than X'00') status, it MUST close the connection.
public struct ClientBasicAuthenticationResponse: Hashable {
    
    public let version: UInt8
    
    public let status: UInt8
    
    public var isSuccess: Bool {
        return status == 0
    }
    
    public init(version: UInt8 = 0, status: UInt8) {
        self.version = version
        self.status = status
    }
}

extension ByteBuffer {
    
    mutating func readClientBasicAuthentication() throws -> ClientBasicAuthentication? {
        return parseUnwindingIfNeeded { buffer in
            guard
                let version = buffer.readInteger(as: UInt8.self),
                let lengthOfUsername = buffer.readInteger(as: UInt8.self),
                buffer.readableBytes >= lengthOfUsername
            else {
                return nil
            }
            
            let username = buffer.readString(length: Int(lengthOfUsername))!
            
            guard
                let lenthOfPassword = buffer.readInteger(as: UInt8.self),
                buffer.readableBytes >= lenthOfPassword
            else {
                return nil
            }
            
            let password = buffer.readString(length: Int(lenthOfPassword))!
            
            return .init(version: version, username: username, password: password)
        }
    }
    
    @discardableResult mutating func writeClientBasicAuthentication(_ authentication: ClientBasicAuthentication) -> Int {
        var written = 0
        
        written += writeInteger(authentication.version)
        written += writeInteger(UInt8(authentication.username.count))
        written += writeString(authentication.username)
        written += writeInteger(UInt8(authentication.password.count))
        written += writeString(authentication.password)

        return written
    }
    
    mutating func readClientBasicAuthenticationResponse() throws -> ClientBasicAuthenticationResponse? {
        return parseUnwindingIfNeeded { buffer in
            guard let version = buffer.readInteger(as: UInt8.self),
                    let status = buffer.readInteger(as: UInt8.self) else {
                    return nil
            }
            
            return .init(version: version, status: status)
        }
    }
    
    @discardableResult mutating func writeClientBasicAuthenticationResponse(_ response: ClientBasicAuthenticationResponse) -> Int {
        var written = 0
        
        written += writeInteger(response.version)
        written += writeInteger(response.status)
        
        return written
    }
}
