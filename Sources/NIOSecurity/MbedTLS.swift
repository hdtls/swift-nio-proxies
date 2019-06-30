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

import CNIOMbedCrypto

func mbedtls_cipher_init(_ algorithm: Algorithm) throws -> UnsafePointer<mbedtls_cipher_info_t> {

    var cipherName = algorithm.rawValue.uppercased()

    switch algorithm {
    case .rc4, .rc4md5:
        cipherName = "ARC4-128"
    case .aes128cfb, .aes192cfb, .aes256cfb, .camellia128cfb, .camellia192cfb, .camellia256cfb:
        cipherName.append("128")
    case .bfcfb:
        cipherName = "BLOWFISH-CFB64"
    default:
        break
    }

    guard let cipher = mbedtls_cipher_info_from_string(cipherName) else {
        throw CryptoError.notFound
    }

    return cipher
}
