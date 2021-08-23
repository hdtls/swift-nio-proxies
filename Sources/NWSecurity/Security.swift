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

import CNWLibmbedcrypto

public func EVP_BytesToKey(_ algorithm: Algorithm, pwd: String) -> [UInt8] {
    guard !pwd.isEmpty else {
        return []
    }

    guard let md = mbedtls_md_info_from_type(MBEDTLS_MD_MD5) else {
        preconditionFailure("MD5 Digest not found in crypto library")
    }

    var ctx: mbedtls_md_context_t = .init()
    var buf: [UInt8] = allocate(Int(MBEDTLS_MD_MAX_SIZE))
    var addmd = 0
    var key: [UInt8] = allocate(algorithm.keyLength)

    var mutableBytes = Array(pwd.utf8)

    let mds = mbedtls_md_get_size(md)
    var j = 0

    memset(&ctx, 0, MemoryLayout<mbedtls_md_context_t>.size)

    if mbedtls_md_setup(&ctx, md, 1) != 0 {
        return []
    }

    while j < algorithm.keyLength {

        mbedtls_md_starts(&ctx)

        if addmd != 0 {
            mbedtls_md_update(&ctx, &buf, Int(mds))
        }

        mbedtls_md_update(&ctx, &mutableBytes, mutableBytes.count)
        mbedtls_md_finish(&ctx, &buf)

        var i = 0
        while i < Int(mds) {
            if j >= algorithm.keyLength {
                break
            }
            key[j] = buf[i]

            i += 1
            j += 1
        }

        addmd += 1
    }

    mbedtls_md_free(&ctx)

    return key
}

public final class Security {

    public let algorithm: Algorithm
    public var key: [UInt8]

    public convenience init(algorithm: Algorithm, password: String) {
        self.init(
            algorithm: algorithm,
            key: EVP_BytesToKey(algorithm, pwd: password)
        )
    }

    public init(algorithm: Algorithm, key: [UInt8]) {
        self.algorithm = algorithm
        self.key = key
    }
}

extension Security: Cryptors {

    public func makeEncryptor() throws -> Cryptor & Updatable {
        switch algorithm {
        case .salsa20,
             .chacha20,
             .chacha20ietf,
             .xchacha20:
            return try SodiumStream.init(algorithm: algorithm, key: key, mode: .encrypt)
        case .rc4,
             .rc4md5,
             .aes128cfb,
             .aes192cfb,
             .aes256cfb,
             .aes128ctr,
             .aes192ctr,
             .aes256ctr,
             .camellia128cfb,
             .camellia192cfb,
             .camellia256cfb,
             .bfcfb:
            return try MbedTLSStream.init(algorithm: algorithm, key: key, mode: .encrypt)
        case .aes128gcm,
             .aes192gcm,
             .aes256gcm:
            return try MbedTLSAEAD.init(algorithm: algorithm, key: key, mode: .encrypt)
        case .chacha20poly1305,
             .chacha20ietfpoly1305,
             .xchacha20ietfpoly1305:
            return try SodiumAEAD.init(algorithm: algorithm, key: key, mode: .encrypt)
        }
    }

    public func makeDecryptor() throws -> Cryptor & Updatable {
        switch algorithm {
        case .salsa20,
             .chacha20,
             .chacha20ietf,
             .xchacha20:
            return try SodiumStream.init(algorithm: algorithm, key: key, mode: .decrypt)
        case .rc4,
             .rc4md5,
             .aes128cfb,
             .aes192cfb,
             .aes256cfb,
             .aes128ctr,
             .aes192ctr,
             .aes256ctr,
             .camellia128cfb,
             .camellia192cfb,
             .camellia256cfb,
             .bfcfb:
            return try MbedTLSStream.init(algorithm: algorithm, key: key, mode: .decrypt)
        case .aes128gcm,
             .aes192gcm,
             .aes256gcm:
            return try MbedTLSAEAD.init(algorithm: algorithm, key: key, mode: .decrypt)
        case .chacha20poly1305,
             .chacha20ietfpoly1305,
             .xchacha20ietfpoly1305:
            return try SodiumAEAD.init(algorithm: algorithm, key: key, mode: .decrypt)
        }
    }
}
