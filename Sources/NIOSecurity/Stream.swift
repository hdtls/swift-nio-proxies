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
import CNIOSecurityShims

let NIOSecurity_AEAD_BLOCK_SIZE = 64;

final class SodiumStream: Cryptor, Updatable {

    let algorithm: Algorithm
    let key: [UInt8]
    var iv: [UInt8]
    let mode: Mode

    private var isHEAD: Bool = true
    private var NIOSecurity_AEAD_CNT: Int = 0

    private let cipher: (UnsafeMutablePointer<UInt8>?, UnsafePointer<UInt8>?, UInt64, UnsafePointer<UInt8>?, UInt64, UnsafePointer<UInt8>?) -> Int8

    init(algorithm: Algorithm, key: [UInt8], mode: Mode) throws {

        guard CNIOSecurityShims_SECURITY_init() >= 0 else {
            throw SecurityError.securityNotAvailable
        }

        switch algorithm {
        case .salsa20:
            cipher = CNIOSecurityShims_STREAM_salsa20
        case .chacha20:
            cipher = CNIOSecurityShims_STREAM_chacha20
        case .chacha20ietf:
            cipher = CNIOSecurityShims_STREAM_chacha20_ietf
        case .xchacha20:
            cipher = CNIOSecurityShims_STREAM_xchacha20
        default:
            throw SecurityError.missingALGO(algorithm: algorithm)
        }

        self.algorithm = algorithm
        self.key = key
        self.iv = [UInt8].random(algorithm.ivLength)
        self.mode = mode
    }

    func update(_ bytes: ArraySlice<UInt8>, isLast: Bool) throws -> Array<UInt8> {

        var mutableBytes = Array(bytes)

        if isHEAD, mode == .decrypt {

            // A stream cipher encrypted TCP stream starts with a randomly generated
            // initializaiton vector, followed by encrypted payload data.
            // [IV][encrypted payload]
            // so when a new TCP stream arrived we need parse IV data.
            if bytes.count >= algorithm.ivLength {
                iv = Array(mutableBytes[..<algorithm.ivLength])
                mutableBytes = Array(mutableBytes[algorithm.ivLength...])
            } else {
                throw SecurityError.securitySetupFailed(reason: .invalidIV)
            }
        }

        let inLength = mutableBytes.count

        // Prepend padding to make the encryption to align to the blocks
        let padding = NIOSecurity_AEAD_CNT % NIOSecurity_AEAD_BLOCK_SIZE

        var buf: [UInt8] = allocate(padding + inLength)

        if padding != 0 {
            var byteBuffer: [UInt8] = allocate(padding)
            byteBuffer.append(contentsOf: mutableBytes)
            mutableBytes = byteBuffer
        }

        var iv = self.iv
        var key = self.key
        _ = cipher(&buf,
                   &mutableBytes,
                   UInt64(inLength + padding),
                   &iv,
                   UInt64(NIOSecurity_AEAD_CNT / NIOSecurity_AEAD_BLOCK_SIZE),
                   &key)

        NIOSecurity_AEAD_CNT += inLength

        var payload = Array(buf[padding..<padding + inLength])

        if isHEAD && mode == .encrypt {
            payload = iv + payload
        }

        isHEAD = false

        return payload
    }
}

func NIOSecurity_cipher_info_from_ALGO(_ algorithm: Algorithm) throws -> UnsafePointer<mbedtls_cipher_info_t> {

    switch algorithm {
    case .rc4:
        return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_ARC4_128)
    case .rc4md5:
        return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_ARC4_128)
    case .aes128cfb:
        return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CFB128)
    case .aes192cfb:
        return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_192_CFB128)
    case .aes256cfb:
        return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CFB128)
    case .aes128ctr:
        return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CTR)
    case .aes192ctr:
        return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_192_CTR)
    case .aes256ctr:
        return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CTR)
    case .aes128gcm:
        return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_GCM)
    case .aes192gcm:
        return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_192_GCM)
    case .aes256gcm:
        return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_GCM)
    case .camellia128cfb:
        return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_CAMELLIA_128_CFB128)
    case .camellia192cfb:
        return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_CAMELLIA_192_CFB128)
    case .camellia256cfb:
        return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_CAMELLIA_256_CFB128)
    case .bfcfb:
        return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_BLOWFISH_CFB64)
    default:
        throw SecurityError.missingALGO(algorithm: algorithm)
    }
}

final class MbedTLSStream: Cryptor, Updatable {

    let algorithm: Algorithm
    let key: [UInt8]
    var iv: [UInt8]
    let mode: Mode

    private var context: mbedtls_cipher_context_t
    private let cipher: UnsafePointer<mbedtls_cipher_info_t>

    /// This property is use to determise whether the p is the first package.
    private var isHEAD: Bool

    init(algorithm: Algorithm, key: [UInt8], mode: Mode) throws {

        cipher = try NIOSecurity_cipher_info_from_ALGO(algorithm)

        self.algorithm = algorithm
        self.key = key
        self.iv = [UInt8].random(algorithm.ivLength)
        self.mode = mode
        self.isHEAD = true

        self.context = .init()
    }

    private func mbedTLSSetup() throws {

        guard mbedtls_cipher_setup(&context, cipher) == 0 else {
            mbedtls_cipher_free(&context)
            throw SecurityError.securityNotAvailable
        }

        let size = algorithm.ivLength + algorithm.keyLength
        var trueKey: [UInt8] = allocate(size)
        var ivLength: Int

        if algorithm == .rc4md5 {
            var nonce = key + iv
            mbedtls_md5(&nonce, size, &trueKey)
            ivLength = 0
        } else {
            trueKey = key
            ivLength = algorithm.ivLength
        }

        let op: mbedtls_operation_t = mode == .encrypt ? MBEDTLS_ENCRYPT : MBEDTLS_DECRYPT

        guard mbedtls_cipher_setkey(&context, &trueKey, Int32(algorithm.keyLength * 8), op) == 0 else {
            mbedtls_cipher_free(&context)
            throw SecurityError.securitySetupFailed(reason: .invalidKey)
        }

        guard mbedtls_cipher_set_iv(&context, &iv, ivLength) == 0 else {
            mbedtls_cipher_free(&context)
            throw SecurityError.securitySetupFailed(reason: .invalidIV)
        }

        guard mbedtls_cipher_reset(&context) == 0 else {
            mbedtls_cipher_free(&context)
            throw SecurityError.securitySetupFailed(reason: .invalidData)
        }
    }

    func update(_ bytes: ArraySlice<UInt8>, isLast: Bool) throws -> Array<UInt8> {

        var mutableBytes = bytes

        if isHEAD, mode == .decrypt {

            if bytes.count >= algorithm.ivLength {
                iv = Array(mutableBytes[..<algorithm.ivLength])
                mutableBytes = mutableBytes[algorithm.ivLength...]
            } else {
                throw SecurityError.securitySetupFailed(reason: .invalidIV)
            }
        }

        if isHEAD {
            try mbedTLSSetup()
        }

        let inLength = mutableBytes.count

        var outLength = 0

        var buf: [UInt8] = allocate(inLength)

        _ = mutableBytes.withUnsafeBufferPointer({
            mbedtls_cipher_update(&context,
                                  $0.baseAddress,
                                  inLength,
                                  &buf,
                                  &outLength)
        })

        var payload: [UInt8] = Array(buf[..<outLength])

        if isHEAD && mode == .encrypt {
                payload = iv + payload
        }

        return payload
    }

    deinit {
        mbedtls_cipher_free(&context)
    }
}
