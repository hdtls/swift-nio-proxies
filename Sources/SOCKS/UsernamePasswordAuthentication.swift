//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2021 Junfeng Zhang
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIO
import Helpers

/// The SOCKS V5 Username/Password Authentication request, defined in RFC 1929.
public struct UsernamePasswordAuthentication: Hashable {
    
    /// The VER field contains the current version of the subnegotiation, which is X'01'.
    public let version: UInt8
    
    /// The UNAME field contains the username as known to the source operating system.
    public let username: String
    
    /// The PASSWD field contains the password association with the given UNAME.
    public let password: String
    
    /// Create a new `UsernamePasswordAuthentication`
    /// - Parameters:
    ///   - version: The authentication subnegotiation version
    ///   - username: The authentication username
    ///   - password: The authentication password
    public init(version: UInt8 = 1, username: String, password: String) {
        self.version = version
        self.username = username
        self.password = password
    }
}

/// The SOCKS V5 Username/Password Authentication response.
public struct UsernamePasswordAuthenticationResponse: Hashable {
    
    /// The version of the subnegotiation
    public let version: UInt8
    
    /// The status of authentication
    /// A STATUS field of X'00' indicates success.
    /// If the server returns a `failure' (STATUS value other than X'00') status,
    /// it MUST close the connection.
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
    
    mutating func readUsernamePasswordAuthentication() throws -> UsernamePasswordAuthentication? {
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
    
    @discardableResult mutating func writeUsernamePasswordAuthentication(_ authentication: UsernamePasswordAuthentication) -> Int {
        var written = 0
        
        written += writeInteger(authentication.version)
        written += writeInteger(UInt8(authentication.username.count))
        written += writeString(authentication.username)
        written += writeInteger(UInt8(authentication.password.count))
        written += writeString(authentication.password)
        
        return written
    }
    
    mutating func readUsernamePasswordAuthenticationResponse() throws -> UsernamePasswordAuthenticationResponse? {
        return parseUnwindingIfNeeded { buffer in
            guard let version = buffer.readInteger(as: UInt8.self),
                  let status = buffer.readInteger(as: UInt8.self) else {
                      return nil
                  }
            
            return .init(version: version, status: status)
        }
    }
    
    @discardableResult mutating func writeClientBasicAuthenticationResponse(_ response: UsernamePasswordAuthenticationResponse) -> Int {
        var written = 0
        
        written += writeInteger(response.version)
        written += writeInteger(response.status)
        
        return written
    }
}
