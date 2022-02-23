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
import Crypto

public struct Account {

    /// ID is the main ID of the account.
    public var id: UUID
    
    /// AlterIDs are the alternative IDs of the account.
    public var alterIDs: [UUID]
    
    /// Security type of the account. Used for client connections.
    public var security: Algorithm
        
    public var authenticatedLengthExperiment: Bool = false
}

/// A enum representing a VMESS protocol version.
public struct ProtocolVersion: Equatable, Codable {

    public static let v1 = ProtocolVersion.init(rawValue: 0x01)
    
    public var rawValue: UInt8
    
    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }
}

public struct VMESSRequestHead: Equatable {
    
    /// The VMESS protocol version.
    public var version: ProtocolVersion = .v1
 
    public var command: Command

    public var options: Options

    /// Specify the encryption method of the data part, the optional values are:
    /// - 0x00: AES-128-CFB;
    /// - 0x01: No encryption;
    /// - 0x02: AES-128-GCM;
    /// - 0x03: ChaCha20-Poly1305;
    public var algorithm: Algorithm
    
    public var address: NetAddress
    
//    public var user: MemoryUser
}


fileprivate enum __AddrID: UInt8 {
    /// IP V4 address: X'01'
    case v4 = 0x01
    
    /// DOMAINNAME: X'02'
    case domain = 0x02
    
    /// IP V6 address
    case v6 = 0x03
}

public enum Algorithm: UInt8 {
    case aes128cfb = 1
    case aes128gcm = 3
    case chacha20poly1305 = 4
    case none = 5
    case zero = 6
    
    var shouldEnablePadding: Bool {
        self == .aes128gcm || self == .chacha20poly1305
    }
}

public struct Options: OptionSet {
    
    public typealias RawValue = UInt8

    public var rawValue: UInt8
    
    /// Standard
    public static let chunkStream = Options.init(rawValue: 1 << 0)
    public static let connectionReuse = Options.init(rawValue: 1 << 1)
    public static let chunkMasking = Options.init(rawValue: 1 << 2)
    public static let globalPadding = Options.init(rawValue: 0x08)
    public static let authenticatedLength = Options.init(rawValue: 0x10)
    
    public init(rawValue: RawValue) {
        self.rawValue = rawValue
    }
}

public struct Command: Equatable {

    public static let tcp = Command.init(rawValue: 0x01)
    public static let udp = Command.init(rawValue: 0x02)
    public static let mux = Command.init(rawValue: 0x03)

    public let rawValue: UInt8
    
    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }
}
