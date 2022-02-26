//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2022 Junfeng Zhang. and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore

/// `Request` object defines VMESS request infomation.
public struct Request {
    
    /// The VMESS protocol version.
    public var version: ProtocolVersion = .v1
    
    /// Request command.
    public var command: Command
    
    /// Current request stream options.
    public var options: StreamOptions
    
    /// The encryption method.
    public var algorithm: Algorithm
    
    /// Request socks address or domain port.
    public var address: NetAddress
    
    /// Request body.
    public var body: ByteBuffer?
}
