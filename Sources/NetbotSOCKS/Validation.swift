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

import NIOCore

extension ByteBuffer {
    
    mutating func parseUnwindingIfNeeded<T>(_ closure: (inout ByteBuffer) throws -> T?) rethrows -> T? {
        let save = self
        do {
            guard let value = try closure(&self) else {
                self = save
                return nil
            }
            return value
        } catch {
            self = save
            throw error
        }
    }
}

extension ByteBuffer {
    
    mutating func readAndValidateProtocolVersion() throws -> UInt8? {
        return try parseUnwindingIfNeeded { buffer -> UInt8? in
            guard let version = buffer.readInteger(as: UInt8.self) else {
                return nil
            }
            guard version == 0x05 else {
                throw SOCKSError.invalidProtocolVersion(actual: version)
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
                throw SOCKSError.invalidReservedByte(actual: reserved)
            }
            return reserved
        }
    }
    
}
