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
import CNWLibsodiumcrypto

let NIOSecurity_AEAD_CHUNK_SIZE_MASK = 0x3FFF
let NIOSecurity_AEAD_CHUNK_SIZE = 2
let NIOSecurity_AEAD_SUB_KEY = "ss-subkey"

enum Mode {
    case encrypt
    case decrypt
}

class AEAD: Cryptor, Updatable {

    let mode: Mode
    let algorithm: Algorithm
    let key: [UInt8]
    var iv: [UInt8]
    let tagLength: Int
    var nonce: [UInt8] = []
    let nonceLength: Int
    var subKey: [UInt8] = []

    private var byteBuffer: [UInt8] = []
    private var pLength: Int = 0
    private var isHEAD: Bool = true

    init(algorithm: Algorithm, key: [UInt8], mode: Mode) throws {
        self.algorithm = algorithm
        self.key = key
        self.iv = [UInt8].random(algorithm.ivLength)
        self.mode = mode
        tagLength = algorithm.tagLength
        nonceLength = algorithm.nonceLength
        nonce = allocate(nonceLength)
    }

    func encrypt(_ bytes: [UInt8]) throws -> [UInt8] {
        var mutableBytes = bytes
        var inLength = mutableBytes.count
        var metadata: [UInt8] = []

        // AEAD cipher has a NIOSecurity_AEAD_CHUNK_SIZE_MASK, we need split data to suit this mask.
        // so CHUNK encryption may be run multiple times.
        while inLength > 0 {
            let copyLength = inLength < NIOSecurity_AEAD_CHUNK_SIZE_MASK ? inLength : NIOSecurity_AEAD_CHUNK_SIZE_MASK
            metadata.append(contentsOf: try encryptChunk(Array(mutableBytes.prefix(copyLength))))
            mutableBytes.removeFirst(copyLength)
            inLength -= copyLength
        }

        return metadata
    }

    func aeadEncrypt(_ bytes: [UInt8]) -> [UInt8] {
        fatalError("this must be overridden by sub class")
    }

    func encryptChunk(_ bytes: [UInt8]) throws -> [UInt8] {
        // An AEAD encrypted TCP stream starts with a randomly generated salt to derive
        // the per-session subkey, followed by any number of encrypted chunks.
        // Each chunk has the following structure:
        // [encrypted payload length][length tag][encrypted payload][payload tag]
        // Payload length is a 2-byte big-endian unsigned integer capped at 0x3FFF. The higher two bits are reserved and must be set to zero. Payload is therefore limited to 16*1024 - 1 bytes.

        let inLength = bytes.count

        var metadata: [[UInt8]] = []
        let pLength = UInt16(inLength & NIOSecurity_AEAD_CHUNK_SIZE_MASK).bigEndian

        metadata = [aeadEncrypt(pLength.uint8)]

        guard metadata[0].count == NIOSecurity_AEAD_CHUNK_SIZE + tagLength else {
            clean()
            throw SecurityError.responseValidationFailed(reason: .invalidLength)
        }

        metadata.append(aeadEncrypt(bytes))

        guard metadata[1].count == inLength + tagLength else {
            clean()
            throw SecurityError.responseValidationFailed(reason: .invalidLength)
        }

        return metadata[0] + metadata[1]
    }

    func aeadDecrypt(_ bytes: [UInt8]) -> [UInt8] {
        fatalError("this must be overridden by sub class")
    }

    func decrypt(_ bytes: [UInt8]) throws -> [UInt8] {

        var plaintext: [UInt8] = []

        byteBuffer.append(contentsOf: bytes)

        while !byteBuffer.isEmpty {
            let payload = try decryptChunk(byteBuffer)

            plaintext.append(contentsOf: payload)

            if payload.isEmpty {
                break
            }
        }

        return plaintext
    }

    func decryptChunk(_ bytes: [UInt8]) throws -> [UInt8] {

        if pLength <= 0 {
            let pLength0 = NIOSecurity_AEAD_CHUNK_SIZE + tagLength

            guard byteBuffer.count > pLength0 else {
                return []
            }

            let p = aeadDecrypt(Array(byteBuffer.prefix(pLength0)))
            pLength = p.withUnsafeBytes {
                Int($0.bindMemory(to: Int16.self).baseAddress!.pointee)
            }

            if (pLength & NIOSecurity_AEAD_CHUNK_SIZE_MASK) != pLength || pLength <= 0 {
                clean()
                pLength = -1
                byteBuffer = []
                throw SecurityError.responseValidationFailed(reason: .invalidLength)
            }

            //            pLength = pLength0
            byteBuffer.removeFirst(NIOSecurity_AEAD_CHUNK_SIZE + tagLength)
        }

        let copyLength = pLength + tagLength

        guard byteBuffer.count >= copyLength else {
            return []
        }

        let plaintext = aeadDecrypt(Array(byteBuffer.prefix(copyLength)))

        if plaintext.count != pLength {
            clean()
            pLength = -1
            byteBuffer = []
            throw SecurityError.responseValidationFailed(reason: .invalidLength)
        }

        pLength = -1
        byteBuffer.removeFirst(copyLength)

        return plaintext
    }

    func update(_ bytes: ArraySlice<UInt8>, isLast: Bool) throws -> Array<UInt8> {
        defer {
            isHEAD = false
        }

        var mutableBytes = bytes

        if isHEAD {
            if mode == .decrypt && mutableBytes.count >= algorithm.ivLength {
                iv = Array(mutableBytes[..<algorithm.ivLength])
                mutableBytes = mutableBytes[algorithm.ivLength...]
            }

            hkdf()
        }

        if mode == .encrypt {
            let payload = try encrypt(Array(mutableBytes))

            return isHEAD ? iv + payload : payload
        } else {
            return try decrypt(Array(mutableBytes))
        }
    }

    private func hkdf() {
        var salt = self.iv
        var key = self.key
        var info: [UInt8] = Array(NIOSecurity_AEAD_SUB_KEY.utf8)
        subKey = allocate(key.count)

        mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1),
                     &salt,
                     iv.count,
                     &key,
                     key.count,
                     &info,
                     info.count,
                     &subKey,
                     key.count)
    }

    func clean() {
        fatalError("this must be overridden by sub class")
    }
}

final class MbedTLSAEAD: AEAD {

    private var context: mbedtls_cipher_context_t = .init()

    override init(algorithm: Algorithm, key: [UInt8], mode: Mode) throws {

        try super.init(algorithm: algorithm, key: key, mode: mode)

        let cipher = try NIOSecurity_cipher_info_from_ALGO(algorithm)

        guard mbedtls_cipher_setup(&context, cipher) == 0 else {
            throw SecurityError.missingALGO(algorithm: algorithm)
        }

        let op = mode == .encrypt ? MBEDTLS_ENCRYPT : MBEDTLS_DECRYPT
        guard mbedtls_cipher_setkey(&context, &subKey, Int32(key.count * 8), op) == 0 else {
            mbedtls_cipher_free(&context)
            throw SecurityError.securitySetupFailed(reason: .invalidKey)
        }

        guard mbedtls_cipher_reset(&context) == 0 else {
            mbedtls_cipher_free(&context)
            throw SecurityError.securitySetupFailed(reason: .invalidData)
        }
    }

    override func aeadEncrypt(_ bytes: [UInt8]) -> [UInt8] {
        var mutableBytes = bytes
        let inLength = mutableBytes.count

        var buf: [UInt8] = allocate(inLength + tagLength)
        var outLength = 0
        var tagBuf: [UInt8] = allocate(tagLength)

        guard mbedtls_cipher_auth_encrypt(&context,
                                          &nonce,
                                          nonceLength,
                                          nil,
                                          0,
                                          &mutableBytes,
                                          inLength,
                                          &buf,
                                          &outLength,
                                          &tagBuf,
                                          tagLength) == 0 else {
                                            return []
        }


        sodium_increment(&nonce, nonceLength)

        return Array(buf[0..<outLength] + tagBuf[0..<tagLength])
    }

    override func clean() {
        mbedtls_cipher_free(&context)
    }

    override func aeadDecrypt(_ bytes: [UInt8]) -> [UInt8] {
        var mutableBytes = bytes
        var outLength = 0
        let pLength = bytes.count - tagLength

        var buf: [UInt8] = allocate(pLength)
        var tag = Array(bytes.dropFirst(pLength))

        guard mbedtls_cipher_auth_decrypt(&context,
                                          &nonce,
                                          nonceLength,
                                          nil,
                                          0,
                                          &mutableBytes,
                                          pLength,
                                          &buf,
                                          &outLength,
                                          &tag,
                                          tagLength) == 0 else {
                                            return []
        }

        sodium_increment(&nonce, nonceLength)

        return Array(buf[0..<outLength])
    }

    deinit {
        mbedtls_cipher_free(&context)
    }
}

final class SodiumAEAD: AEAD {

    private let encipher: (UnsafeMutablePointer<UInt8>, UnsafeMutablePointer<UInt64>?, UnsafePointer<UInt8>?, UInt64, UnsafePointer<UInt8>?, UInt64, UnsafePointer<UInt8>?, UnsafePointer<UInt8>, UnsafePointer<UInt8>) -> Int32
    private let decipher: (UnsafeMutablePointer<UInt8>?, UnsafeMutablePointer<UInt64>?, UnsafeMutablePointer<UInt8>?, UnsafePointer<UInt8>, UInt64, UnsafePointer<UInt8>?, UInt64, UnsafePointer<UInt8>, UnsafePointer<UInt8>) -> Int32

    override init(algorithm: Algorithm, key: [UInt8], mode: Mode) throws {

        guard sodium_init() >= 0 else {
            throw SecurityError.securityNotAvailable
        }

        switch algorithm {
        case .chacha20poly1305:
            encipher = crypto_aead_chacha20poly1305_encrypt
            decipher = crypto_aead_chacha20poly1305_decrypt
        case .chacha20ietfpoly1305:
            encipher = crypto_aead_chacha20poly1305_ietf_encrypt
            decipher = crypto_aead_chacha20poly1305_ietf_decrypt
        case .xchacha20ietfpoly1305:
            encipher = crypto_aead_xchacha20poly1305_ietf_encrypt
            decipher = crypto_aead_xchacha20poly1305_ietf_decrypt
        case .aes256gcm:
            encipher = crypto_aead_aes256gcm_encrypt
            decipher = crypto_aead_aes256gcm_decrypt
        default:
            throw SecurityError.missingALGO(algorithm: algorithm)
        }

        try super.init(algorithm: algorithm, key: key, mode: mode)
    }

    override func aeadEncrypt(_ bytes: [UInt8]) -> [UInt8] {

        var mutableBytes = bytes
        let inLength = bytes.count

        var buf: [UInt8] = allocate(inLength + tagLength)
        var outLength: UInt64 = 0

        guard encipher(&buf, &outLength, &mutableBytes, UInt64(inLength), nil, 0, nil, &nonce, &subKey) == 0 else {
            return []
        }

        guard outLength == inLength + tagLength else {
            return []
        }

        sodium_increment(&nonce, nonceLength)

        return Array(buf[..<Int(outLength)])
    }

    override func aeadDecrypt(_ bytes: [UInt8]) -> [UInt8] {

        var mutableBytes = bytes
        let inLength = bytes.count

        var buf: [UInt8] = allocate(inLength + tagLength)
        var outLength: UInt64 = 0

        guard decipher(&buf, &outLength, nil, &mutableBytes, UInt64(inLength), nil, outLength, &nonce, &subKey) == 0 else {
            return []
        }

        guard outLength == inLength - tagLength else {
            return []
        }

        sodium_increment(&nonce, nonceLength)

        return Array(buf[..<Int(outLength)])
    }

    override func clean() {}
}
