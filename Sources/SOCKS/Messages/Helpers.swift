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

extension ByteBuffer {
    
    mutating func readAndValidateProtocolVersion() throws -> UInt8? {
        return try parseUnwindingIfNeeded { buffer -> UInt8? in
            guard let version = buffer.readInteger(as: UInt8.self) else {
                return nil
            }
            guard version == 0x05 else {
                throw SOCKSError.InvalidProtocolVersion(actual: version)
            }
            return version
        }
    }
    
    mutating func readAndValidateReserved() throws -> UInt8? {
        return try parseUnwindingIfNeeded { buffer -> UInt8? in
            guard let reserved = buffer.readInteger(as: UInt8.self) else {
                return nil
            }
            guard reserved == 0x00 else {
                throw SOCKSError.InvalidReservedByte(actual: reserved)
            }
            return reserved
        }
    }
    
}