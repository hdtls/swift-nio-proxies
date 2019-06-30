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

@inline(__always) func sodium_cipher_update(_ algorithm: Algorithm,
                                            _ output: UnsafeMutablePointer<UInt8>,
                                            _ input: UnsafePointer<UInt8>,
                                            _ cLength: UInt64,
                                            _ nonce: UnsafePointer<UInt8>,
                                            _ block_cnt: UInt64,
                                            _ key: UnsafePointer<UInt8>) -> Int32 {


    switch algorithm {
    case .salsa20:
        return CNIOSecurityShims_STREAM_salsa20(output, input, cLength, nonce, block_cnt, key)
    case .chacha20:
        return CNIOSecurityShims_STREAM_chacha20(output, input, cLength, nonce, block_cnt, key)
    case .xchacha20:
        return CNIOSecurityShims_STREAM_xchacha20(output, input, cLength, nonce, block_cnt, key)
    case .chacha20ietf:
        return CNIOSecurityShims_STREAM_chacha20_ietf(output, input, cLength, nonce, block_cnt, key)
    default:
        return -1
    }
}

final class SodiumStream: Cryptor, Updatable {

    let algorithm: Algorithm
    let key: [UInt8]
    var iv: [UInt8]
    let mode: Mode

    private var isHEAD: Bool = true
    private var counter: Int = 0
    private let blockSize = 64

    init(algorithm: Algorithm, key: [UInt8], mode: Mode) throws {

        guard CNIOSecurityShims_SECURITY_init() >= 0 else {
            throw CryptoError.notFound
        }

        switch algorithm {
        case .salsa20, .chacha20, .chacha20ietf, .xchacha20:
            self.algorithm = algorithm
            self.key = key
            self.iv = [UInt8].random(algorithm.ivLength)
            self.mode = mode
        default:
            throw CryptoError.notFound
        }
    }

    func update(_ bytes: ArraySlice<UInt8>, isLast: Bool) throws -> Array<UInt8> {

        var mutableBytes = Array(bytes)

        if isHEAD, mode == .decrypt {

            if bytes.count >= algorithm.ivLength {
                iv = Array(mutableBytes[..<algorithm.ivLength])
                mutableBytes = Array(mutableBytes[algorithm.ivLength...])
            } else {
                throw MbedTLSError.invalidLength
            }
        }

        let inLength = mutableBytes.count

        // Prepend padding to make the encryption to align to the blocks
        let padding = counter % blockSize

        var buf: [UInt8] = allocate(padding + inLength)

        if padding != 0 {
            var byteBuffer: [UInt8] = allocate(padding)
            byteBuffer.append(contentsOf: mutableBytes)
            mutableBytes = byteBuffer
        }

        var iv = self.iv
        var key = self.key
        _ = sodium_cipher_update(algorithm,
                                 &buf,
                                 &mutableBytes,
                                 UInt64(inLength + padding),
                                 &iv,
                                 UInt64(counter / blockSize),
                                 &key)

        counter += inLength

        let payload = Array(buf[padding..<padding + inLength])

        if isHEAD {
            isHEAD = false

            if mode == .encrypt {
                return iv + payload
            }
        }

        return payload
    }
}

enum MbedTLSError: Error {
    case notFound
    case setupFailure
    case setKeyFailure
    case setIvFailure
    case resetFailure
    case invalidLength
}

final class MbedTLSStream: Cryptor, Updatable {

    let algorithm: Algorithm
    let key: [UInt8]
    var iv: [UInt8]
    let mode: Mode

    private var context: mbedtls_cipher_context_t

    /// This property is use to determise whether the p is the first package.
    private var isHEAD: Bool

    init(algorithm: Algorithm, key: [UInt8], mode: Mode) throws {

        self.algorithm = algorithm
        self.key = key
        self.iv = [UInt8].random(algorithm.ivLength)
        self.mode = mode
        self.isHEAD = true

        let cipher = try mbedtls_cipher_init(algorithm)
        self.context = .init()

        guard mbedtls_cipher_setup(&context, cipher) == 0 else {
            mbedtls_cipher_free(&context)
            throw CryptoError.setupFailure(reason: .invalidData)
        }
    }

    private func mbedTLSSetup() throws {

        var trueKey: [UInt8] = []
        var ivLength: Int

        if algorithm == .rc4md5 {
            var nonce = key + iv
            mbedtls_md5(&nonce, nonce.count, &trueKey)
            ivLength = 0
        } else {
            trueKey = key
            ivLength = algorithm.ivLength
        }

        let op: mbedtls_operation_t = mode == .encrypt ? MBEDTLS_ENCRYPT : MBEDTLS_DECRYPT

        guard mbedtls_cipher_setkey(&context, &trueKey, Int32(algorithm.keyLength * 8), op) == 0 else {
            mbedtls_cipher_free(&context)
            throw CryptoError.setupFailure(reason: .invalidData)
        }

        let success = iv.withUnsafeBufferPointer {
            mbedtls_cipher_set_iv(&context, $0.baseAddress, ivLength) == 0
        }

        guard success else {
            mbedtls_cipher_free(&context)
            throw CryptoError.setupFailure(reason: .invalidData)
        }

        guard mbedtls_cipher_reset(&context) == 0 else {
            mbedtls_cipher_free(&context)
            throw CryptoError.setupFailure(reason: .invalidData)
        }
    }

    func update(_ bytes: ArraySlice<UInt8>, isLast: Bool) throws -> Array<UInt8> {

        var mutableBytes = bytes

        if isHEAD, mode == .decrypt {

            if bytes.count >= algorithm.ivLength {
                iv = Array(mutableBytes[..<algorithm.ivLength])
                mutableBytes = mutableBytes[algorithm.ivLength...]
            } else {
                throw MbedTLSError.invalidLength
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

        if isHEAD {
            isHEAD = false

            if mode == .encrypt {
                return iv + Array(buf.prefix(outLength))
            }
        }
        return Array(buf.prefix(outLength))
    }

    deinit {
        mbedtls_cipher_free(&context)
    }
}
