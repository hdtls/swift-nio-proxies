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

/// `ProtocolVersion` defines SOCKS protocol version.
public struct ProtocolVersion: Codable, Hashable, RawRepresentable {
    
    public var rawValue: UInt8
    
    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }
}

extension ProtocolVersion {
    
    /// SOCKS5.
    public static let v5 = ProtocolVersion.init(rawValue: 0x05)
}
