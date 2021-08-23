//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright © 2019 Netbot Ltd. and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

public enum Algorithm: String, Equatable {

    // Legency
    // Stream ciphers provide only confidentiality. Data integrity and authenticity is not guaranteed. Users should
    // use AEAD ciphers whenever possible.
    case bfcfb = "bf-cfb"

    case salsa20 = "salsa20"

    case chacha20 = "chacha20"
    case chacha20ietf = "chacha20-ietf"

    case xchacha20 = "xchacha20"

    case rc4 = "rc4"
    case rc4md5 = "rc4-md5"

    case aes128cfb = "aes-128-cfb"
    case aes192cfb = "aes-192-cfb"
    case aes256cfb = "aes-256-cfb"

    case aes128ctr = "aes-128-ctr"
    case aes192ctr = "aes-192-ctr"
    case aes256ctr = "aes-256-ctr"

    case camellia128cfb = "camellia-128-cfb"
    case camellia192cfb = "camellia-192-cfb"
    case camellia256cfb = "camellia-256-cfb"

    // AEAD
    // AEAD stands for Authenticated Encryption with Associated Data. AEAD ciphers simultaneously provide
    // confidentiality, integrity, and authenticity. They have excellent performance and power efficiency on modern
    // hardware. Users should use AEAD ciphers whenever possible.
    // The following AEAD ciphers are recommended.
    case aes128gcm = "aes-128-gcm"
    case aes192gcm = "aes-192-gcm"
    case aes256gcm = "aes-256-gcm"

    case chacha20poly1305 = "chcha20-poly1305"
    case chacha20ietfpoly1305 = "chcha20-ietf-poly1305"

    case xchacha20ietfpoly1305 = "xchcha20-ietf-poly1305"

    public var isAEAD: Bool {
        switch self {
        case .aes128gcm:
            fallthrough
        case .aes192gcm:
            fallthrough
        case .aes256gcm:
            fallthrough
        case .chacha20poly1305:
            return true
        default:
            return false
        }
    }

    public var isStream: Bool {
        return !isAEAD
    }

    public static var allValues: [Algorithm] = [
        .bfcfb,
        .chacha20,
        .salsa20,
        .rc4md5,
        .aes128ctr,
        .aes192ctr,
        .aes256ctr,
        .aes128cfb,
        .aes192cfb,
        .aes256cfb,
        .camellia128cfb,
        .camellia192cfb,
        .camellia256cfb,
        .chacha20ietf,
        .aes128gcm,
        .aes192gcm,
        .aes256gcm,
        //        .aes128ocb,
        //        .aes192ocb,
        //        .aes256ocb,
        .chacha20poly1305,
        .chacha20ietfpoly1305,
        .xchacha20ietfpoly1305
    ]
}

extension Algorithm {
    var keyLength: Int {

        switch self {
        case .bfcfb:
            return 16

        case .salsa20:
            return 32

        case .chacha20:
            return 32
        case .chacha20ietf:
            return 32

        case .xchacha20:
            return 32

        case .rc4:
            return 16
        case .rc4md5:
            return 16

        case .aes128ctr:
            return 16
        case .aes192ctr:
            return 24
        case .aes256ctr:
            return 32

        case .aes128cfb:
            return 16
        case .aes192cfb:
            return 24
        case .aes256cfb:
            return 32

        case .camellia128cfb:
            return 16
        case .camellia192cfb:
            return 24
        case .camellia256cfb:
            return 32

        case .aes128gcm:
            return 16
        case .aes192gcm:
            return 24
        case .aes256gcm:
            return 32

        case .chacha20poly1305:
            return 32
        case .chacha20ietfpoly1305:
            return 32
        case .xchacha20ietfpoly1305:
            return 32
        }
    }

    var ivLength: Int {
        switch self {
        case .bfcfb:
            return 8

        case .salsa20:
            return 8

        case .chacha20:
            return 8
        case .chacha20ietf:
            return 12

        case .xchacha20:
            return 24

        case .rc4:
            return 0
        case .rc4md5:
            return 16

        case .aes128ctr,
             .aes192ctr,
             .aes256ctr,

             .aes128cfb,
             .aes192cfb,
             .aes256cfb,

             .camellia128cfb,
             .camellia192cfb,
             .camellia256cfb:
            return 16

        case .aes128gcm,
             .aes192gcm,
             .aes256gcm,

             .chacha20poly1305,
             .chacha20ietfpoly1305,
             .xchacha20ietfpoly1305:
            return keyLength
        }
    }

    var nonceLength: Int {
        switch self {
        case .aes128gcm,
             .aes192gcm,
             .aes256gcm,
             //             .aes128ocb,
        //             .aes192ocb,
        //             .aes256ocb,
        .chacha20poly1305,
        .chacha20ietfpoly1305:
            return 12

        case .xchacha20ietfpoly1305:
            return 24
        default:
            return -1
        }
    }

    var tagLength: Int {
        switch self {
        case .aes128gcm,
             .aes192gcm,
             .aes256gcm,
             //             .aes128ocb,
        //             .aes192ocb,
        //             .aes256ocb,
        .chacha20poly1305,
        .chacha20ietfpoly1305,
        .xchacha20ietfpoly1305:
            return 16
        default:
            return -1
        }
    }
}
