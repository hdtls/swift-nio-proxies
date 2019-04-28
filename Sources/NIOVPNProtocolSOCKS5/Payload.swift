//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright © 2019 Netbot Ltd. All rights reserved. and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation
import struct NIO.ByteBuffer

struct HelloRequest {
    var version: SOCKSVersion
    var numberOfAuthMethods: UInt8
    var methods: [Method]
}

struct HelloResponse {
    var version: SOCKSVersion
    var method: Method
}

struct RELRequest {
    var version: SOCKSVersion
    var cmd: CMD
    var reserved: UInt8 = 0x00
    var addressType: ATYP
    var desiredDestinationAddress: [UInt8]
    var desiredDestinationPort: [UInt8]
}

struct RELReply {
    var version: SOCKSVersion
    var reply: Reply
    var reserved: UInt8
    var addressType: ATYP
    var desiredDestinationAddress: [UInt8]
    var desiredDestinationPort: [UInt8]
}

struct BasicAuthResponse {
    var version: UInt8
    var status: UInt8

    var isSuccess: Bool {
        return version == 0x01 && status == 0x00
    }

    static var success: BasicAuthResponse {
        return .init(version: 0x01, status: 0x00)
    }

    static var failure: BasicAuthResponse {
        return .init(version: 0x01, status: 0x01)
    }
}

struct BasicAuthRequest {
    var version: UInt8
    var uLength: UInt8
    var username: [UInt8]
    var pLength: UInt8
    var passwd: [UInt8]
}
