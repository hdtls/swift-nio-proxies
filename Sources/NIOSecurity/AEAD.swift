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
import CNIOSodium

let AEAD_CHUNK_SIZE_MASK = 0x3FFF
let AEAD_CHUNK_SIZE_LEN = 2

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

        while inLength > 0 {
            let copyLength = inLength < AEAD_CHUNK_SIZE_MASK ? inLength : AEAD_CHUNK_SIZE_MASK
            metadata.append(contentsOf: try encrypt_chunck(Array(mutableBytes.prefix(copyLength))))
            mutableBytes.removeFirst(copyLength)
            inLength -= copyLength
        }

        return metadata
    }

    func aead_encrypt(_ bytes: [UInt8]) -> [UInt8] {
        fatalError("this must be overridden by sub class")
    }

    func encrypt_chunck(_ bytes: [UInt8]) throws -> [UInt8] {

        let inLength = bytes.count

        var metadata: [[UInt8]] = []
        let pLength = UInt16(inLength & AEAD_CHUNK_SIZE_MASK).bigEndian

        metadata = [aead_encrypt(pLength.uint8)]

        guard metadata[0].count == AEAD_CHUNK_SIZE_LEN + tagLength else {
            clean()
            throw MbedTLSError.invalidLength
        }

        metadata.append(aead_encrypt(bytes))

        guard metadata[1].count == inLength + tagLength else {
            clean()
            throw MbedTLSError.invalidLength
        }

        return metadata[0] + metadata[1]
    }

    func aead_decrypt(_ bytes: [UInt8]) -> [UInt8] {
        fatalError("this must be overridden by sub class")
    }

    func decrypt(_ bytes: [UInt8]) throws -> [UInt8] {

        var plaintext: [UInt8] = []

        byteBuffer.append(contentsOf: bytes)

        while !byteBuffer.isEmpty {
            let payload = try decrypt_chunck(byteBuffer)

            plaintext.append(contentsOf: payload)

            if payload.isEmpty {
                break
            }
        }

        return plaintext
    }

    func decrypt_chunck(_ bytes: [UInt8]) throws -> [UInt8] {

        if pLength <= 0 {
            let pLength0 = AEAD_CHUNK_SIZE_LEN + tagLength

            guard byteBuffer.count > pLength0 else {
                return []
            }

            let p = aead_decrypt(Array(byteBuffer.prefix(pLength0)))
            pLength = p.withUnsafeBytes {
                Int($0.bindMemory(to: Int16.self).baseAddress!.pointee)
            }

            if (pLength & AEAD_CHUNK_SIZE_MASK) != pLength || pLength <= 0 {
                clean()
                pLength = -1
                byteBuffer = []
                throw MbedTLSError.invalidLength
            }

            //            pLength = pLength0
            byteBuffer.removeFirst(AEAD_CHUNK_SIZE_LEN + tagLength)
        }

        let copyLength = pLength + tagLength

        guard byteBuffer.count >= copyLength else {
            return []
        }

        let plaintext = aead_decrypt(Array(byteBuffer.prefix(copyLength)))

        if plaintext.count != pLength {
            clean()
            pLength = -1
            byteBuffer = []
            throw MbedTLSError.invalidLength
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

        if isHEAD, mode == .decrypt {
            if mutableBytes.count >= algorithm.ivLength {
                iv = Array(mutableBytes[..<algorithm.ivLength])
                mutableBytes = mutableBytes[algorithm.ivLength...]
            }
        }

        if isHEAD {
            deliverKey()
        }

        if mode == .encrypt {
            let payload = try encrypt(Array(mutableBytes))
            if isHEAD {
                return iv + payload
            }
            return payload
        } else {
            return try decrypt(Array(mutableBytes))
        }
    }

    private func deliverKey() {
        var salt = self.iv
        var key = self.key
        var info: [UInt8] = Array("ss-subkey".utf8)
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

        let cipher = try mbedtls_cipher_init(algorithm)

        guard mbedtls_cipher_setup(&context, cipher) == 0 else {
            throw MbedTLSError.setupFailure
        }

        let op = mode == .encrypt ? MBEDTLS_ENCRYPT : MBEDTLS_DECRYPT
        guard mbedtls_cipher_setkey(&context, &subKey, Int32(key.count * 8), op) == 0 else {
            mbedtls_cipher_free(&context)
            throw MbedTLSError.setKeyFailure
        }

        guard mbedtls_cipher_reset(&context) == 0 else {
            mbedtls_cipher_free(&context)
            throw MbedTLSError.resetFailure
        }
    }

    override func aead_encrypt(_ bytes: [UInt8]) -> [UInt8] {
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

        unique(&nonce, nonceLength)

        return Array(buf[0..<outLength] + tagBuf[0..<tagLength])
    }

    override func clean() {
        mbedtls_cipher_free(&context)
    }

    override func aead_decrypt(_ bytes: [UInt8]) -> [UInt8] {
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

        unique(&nonce, nonceLength)

        return Array(buf[0..<outLength])
    }

    deinit {
        mbedtls_cipher_free(&context)
    }
}

final class SodiumAEAD: AEAD {

    private let encryptor: (UnsafeMutablePointer<UInt8>, UnsafeMutablePointer<UInt64>?, UnsafePointer<UInt8>?, UInt64, UnsafePointer<UInt8>?, UInt64, UnsafePointer<UInt8>?, UnsafePointer<UInt8>, UnsafePointer<UInt8>) -> Int32
    private let decryptor: (UnsafeMutablePointer<UInt8>?, UnsafeMutablePointer<UInt64>?, UnsafeMutablePointer<UInt8>?, UnsafePointer<UInt8>, UInt64, UnsafePointer<UInt8>?, UInt64, UnsafePointer<UInt8>, UnsafePointer<UInt8>) -> Int32

    override init(algorithm: Algorithm, key: [UInt8], mode: Mode) throws {
        _ = sodium_init()

        switch algorithm {
        case .chacha20poly1305:
            encryptor = crypto_aead_chacha20poly1305_encrypt
            decryptor = crypto_aead_chacha20poly1305_decrypt
        case .chacha20ietfpoly1305:
            encryptor = crypto_aead_chacha20poly1305_ietf_encrypt
            decryptor = crypto_aead_chacha20poly1305_ietf_decrypt
        case .xchacha20ietfpoly1305:
            encryptor = crypto_aead_xchacha20poly1305_ietf_encrypt
            decryptor = crypto_aead_xchacha20poly1305_ietf_decrypt
        case .aes256gcm:
            encryptor = crypto_aead_aes256gcm_encrypt
            decryptor = crypto_aead_aes256gcm_decrypt
        default:
            throw CryptoError.notFound
        }

        try super.init(algorithm: algorithm, key: key, mode: mode)
    }

    override func aead_encrypt(_ bytes: [UInt8]) -> [UInt8] {

        var mutableBytes = bytes
        let inLength = bytes.count

        var buf: [UInt8] = allocate(inLength + tagLength)
        var outLength: UInt64 = 0

        guard encryptor(&buf, &outLength, &mutableBytes, UInt64(inLength), nil, 0, nil, &nonce, &subKey) == 0 else {
            return []
        }

        guard outLength == inLength + tagLength else {
            return []
        }

        unique(&nonce, nonceLength)

        return Array(buf[..<Int(outLength)])
    }

    override func aead_decrypt(_ bytes: [UInt8]) -> [UInt8] {

        var mutableBytes = bytes
        let inLength = bytes.count

        var buf: [UInt8] = allocate(inLength + tagLength)
        var outLength: UInt64 = 0

        guard decryptor(&buf, &outLength, nil, &mutableBytes, UInt64(inLength), nil, outLength, &nonce, &subKey) == 0 else {
            return []
        }

        guard outLength == inLength - tagLength else {
            return []
        }

        unique(&nonce, nonceLength)

        return Array(buf[..<Int(outLength)])
    }

    override func clean() {}
}
