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
import NIO

// The SOCKS5 protocol is defined in [RFC 1928](https://tools.ietf.org/html/rfc1928)
enum SOCKSVersion: UInt8 {
    case v5 = 0x05
}

/// SOCKS5 Authentication METHOD
///
enum Method: UInt8 {
    /// - noAuth: X'00' NO AUTHENTICATION REQUIRED
    case noAuth = 0x00

    /// - GSSAPI: X'01' GSSAPI
    case GSSAPI = 0x01

    /// - basicAuth: X'02' USERNAME/PASSWORD
    case basicAuth = 0x02

    /// - IANA: X'03' to X'7F' IANA ASSIGNED
    case IANA = 0x03

    /// - `private`: X'80' to X'FE' RESERVED FOR PRIVATE METHODS
    case `private` = 0x80

    /// - noAcceptableMethods: X'FF' NO ACCEPTABLE METHODS
    case noAcceptableMethods = 0xff

    init?(rawValue: UInt8) {
        switch rawValue {
        case 0x00: self = .noAuth
        case 0x01: self = .GSSAPI
        case 0x02: self = .basicAuth
        case 0x03...0x7f: self = .IANA
        case 0x08...0xfe: self = .private
        case 0xff: self = .noAcceptableMethods
        default: return nil
        }
    }
}

/// SOCKS5 Address type
///
/// - ipv4
/// - domainLength
/// - ipv6
enum ATYP: UInt8 {
    case ipv4 = 0x01
    case domainLength = 0x03
    case ipv6 = 0x04
}

/// The SOCKS request details command filed
///
enum CMD: UInt8 {
    /// - connect: CONNECT X'01'
    case connect = 0x01

    /// - bind: BIND X'02'
    case bind = 0x02

    /// - udp: UDP ASSOCIATE X'03'
    case udp = 0x03
}

/// The SOCKS replies Reply field
///
enum Reply: UInt8 {
    /// - succeeded: X'00' succeeded
    case succeeded = 0x00

    /// - generalSOCKSServerFailure: X'01' general SOCKS server failure
    case generalSOCKSServerFailure = 0x01

    /// - connectionNotAllowedByRuleset: X'02' connection not allowed by ruleset
    case connectionNotAllowedByRuleset = 0x02

    /// - networkUnreachable: X'03' Network unreachable
    case networkUnreachable = 0x03

    /// - hostUnreachable: X'04' Host unreachable
    case hostUnreachable = 0x04

    /// - connectionRefused: X'05' Connection refused
    case connectionRefused = 0x05

    /// - TTLExpired: X'06' TTL expired
    case TTLExpired = 0x06

    /// - commandNotSupported: X'07' Command not supported
    case commandNotSupported = 0x07

    /// - addressTypeNotSupported: X'08' Address type not supported
    case addressTypeNotSupported = 0x08

    /// - unassigned: X'09' to X'FF' unassigned
    case unassigned = 0x09
}
