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

/// Wrapper for SOCKS protcol error.
public enum SOCKSError: Error {
    
    /// The SOCKS client was in a different state to that required.
    case invalidClientState
    
    /// The SOCKS server was in a different state to that required.
    case invalidServerState
    
        /// The protocol version was something other than *5*. Note that
        /// we currently only supported SOCKv5.
    case invalidProtocolVersion(actual: UInt8)
    
        /// Reserved bytes should always be the `NULL` byte *0x00*. Something
        /// else was encountered.
    case invalidReservedByte(actual: UInt8)
    
        /// SOCKSv5 only supports IPv4 (*0x01*), IPv6 (*0x04*), or FQDN(*0x03*).
    case invalidAddressType(actual: UInt8)
    
        /// The server selected an authentication method not supported by the client.
    case invalidAuthenticationSelection(selection: AuthenticationMethod)
    
        /// The client and server were unable to agree on an authentication method.
    case noValidAuthenticationMethod
    
    case invalidCredential

        /// Missing authentication credential.
    case missingCredential
    
        ///  The SOCKS server failed to connect to the target host.
    case connectionFailed(reply: SOCKSServerReply)
    
        /// The client or server receieved data when it did not expect to.
    case unexpectedRead
    
    /// The SOCKS client was in a different state to that required.
    public struct InvalidClientState: Error, Hashable {
        public init() {
            
        }
    }
    
    /// The SOCKS server was in a different state to that required.
    public struct InvalidServerState: Error, Hashable {
        public init() {
            
        }
    }
    
    /// The protocol version was something other than *5*. Note that
    /// we currently only supported SOCKv5.
    public struct InvalidProtocolVersion: Error, Hashable {
        public var actual: UInt8
        public init(actual: UInt8) {
            self.actual = actual
        }
    }

    /// Reserved bytes should always be the `NULL` byte *0x00*. Something
    /// else was encountered.
    public struct InvalidReservedByte: Error, Hashable {
        public var actual: UInt8
        public init(actual: UInt8) {
            self.actual = actual
        }
    }

    /// SOCKSv5 only supports IPv4 (*0x01*), IPv6 (*0x04*), or FQDN(*0x03*).
    public struct InvalidAddressType: Error, Hashable {
        public var actual: UInt8
        public init(actual: UInt8) {
            self.actual = actual
        }
    }

    /// The server selected an authentication method not supported by the client.
    public struct InvalidAuthenticationSelection: Error, Hashable {
        public var selection: AuthenticationMethod
        public init(selection: AuthenticationMethod) {
            self.selection = selection
        }
    }

    /// The client and server were unable to agree on an authentication method.
    public struct NoValidAuthenticationMethod: Error, Hashable {
        public init() {
            
        }
    }
    
    public struct MissingCredential: Error, Hashable {
        public init() {}
    }

    ///  The SOCKS server failed to connect to the target host.
    public struct ConnectionFailed: Error, Hashable {
        public var reply: SOCKSServerReply
        public init(reply: SOCKSServerReply) {
            self.reply = reply
        }
    }
    
    /// The client or server receieved data when it did not expect to.
    public struct UnexpectedRead: Error, Hashable {
        public init() {
            
        }
    }
    
}
