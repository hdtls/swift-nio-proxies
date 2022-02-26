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

import Foundation
import NetbotHelpers

/// VMESS protocol response data object.
public struct Response {
    
    /// Authentication code.
    public var authenticationCode: UInt8
    
    /// Stream options.
    public var options: StreamOptions
    
    /// Command code.
    public var commandCode: UInt8
    
    /// Command.
    public var command: ResponseCommand?
    
    /// Plain response body data.
    public var body: Data?
}

public protocol ResponseCommand {}

public struct SwitchAccountCommand: ResponseCommand {
        
    var id: UUID
    
    var level: UInt32
    
    var countOfAlterIDs: UInt16
    
    var address: NetAddress?

    var validMin: UInt8
}
