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

import XCTest
@testable import NWSecurity

func makeEncryptor(with algorithm: Algorithm) throws -> Cryptor & Updatable {
    return try Security.init(algorithm: algorithm, password: "Netbot").makeEncryptor()
}

func makeDecryptor(with algorithm: Algorithm) throws -> Cryptor & Updatable {
    return try Security.init(algorithm: algorithm, password: "Netbot").makeDecryptor()
}

final class NIOSecurityTests: XCTestCase {

    lazy var metadata: [UInt8] = {

        let blockSize = 16385
        let rounds = 10
        var plain: [UInt8] = []

        for _ in 0..<blockSize * rounds {
            plain.append(UInt8.random(in: 0...UInt8.max))
        }

        return plain
    }()

    func testSALSA() throws {
        XCTAssertNoThrow(try makeEncryption(with: .salsa20))
    }

    func testRC4() throws {
        XCTAssertNoThrow(try makeEncryption(with: .rc4))
    }

    func testRC4MD5() throws {
        XCTAssertNoThrow(try makeEncryption(with: .rc4md5))
    }

    func testBlowfish() throws {
        XCTAssertNoThrow(try makeEncryption(with: .bfcfb))
    }

    func testAES128CFB() throws {
        XCTAssertNoThrow(try makeEncryption(with: .aes128cfb))
    }

    func testAES192CFB() throws {
        XCTAssertNoThrow(try makeEncryption(with: .aes192cfb))
    }

    func testAES256CFB() throws {
        XCTAssertNoThrow(try makeEncryption(with: .aes256cfb))
    }

    func testAES128CTR() throws {
        XCTAssertNoThrow(try makeEncryption(with: .aes128ctr))
    }

    func testAES192CTR() throws {
        XCTAssertNoThrow(try makeEncryption(with: .aes192ctr))
    }

    func testAES256CTR() throws {
        XCTAssertNoThrow(try makeEncryption(with: .aes256ctr))
    }

    func testCAMELLIA128CFB() throws {
        XCTAssertNoThrow(try makeEncryption(with: .camellia128cfb))
    }

    func testCAMELLIA192CFB() throws {
        XCTAssertNoThrow(try makeEncryption(with: .camellia192cfb))
    }

    func testCAMELLIA256CFB() throws {
        XCTAssertNoThrow(try makeEncryption(with: .camellia256cfb))
    }

    func testCHACHA20() throws {
        XCTAssertNoThrow(try makeEncryption(with: .chacha20))
    }

    func testXCHACHA20() throws {
        XCTAssertNoThrow(try makeEncryption(with: .xchacha20))
    }

    func testCHACHA20IETF() throws {
        XCTAssertNoThrow(try makeEncryption(with: .chacha20ietf))
    }

    func testAES128GCM() throws {
        XCTAssertNoThrow(try makeEncryption(with: .aes128gcm))
    }

    func testAES192GCM() throws {
        XCTAssertNoThrow(try makeEncryption(with: .aes192gcm))
    }

    func testAES256GCM() throws {
        XCTAssertNoThrow(try makeEncryption(with: .aes256gcm))
    }

    func testCHACHA20Poly1305() throws {
        XCTAssertNoThrow(try makeEncryption(with: .chacha20poly1305))
    }

    func testCHACHA20IETFPoly1305() throws {
        XCTAssertNoThrow(try makeEncryption(with: .chacha20ietfpoly1305))
    }

    func testXCHACHA20IETFPoly1305() throws {
        XCTAssertNoThrow(try makeEncryption(with: .xchacha20ietfpoly1305))
    }

    func makeEncryption(with algorithm: Algorithm) throws {

        let encryptor = try makeEncryptor(with: algorithm)
        let decryptor = try makeDecryptor(with: algorithm)

        var ciphertext:[[UInt8]] = []
        var pos = 0

        while pos < metadata.count {
            let copy = Int.random(in: 100...32768)
            let copyLength = pos + copy > metadata.count ? metadata.count - pos : copy
            let r = try encryptor.update(metadata[pos..<pos + copyLength])
            ciphertext.append(r)
            pos += copyLength
        }

        pos = 0
        var plaintext: [UInt8] = []

        for c in ciphertext {
            plaintext.append(contentsOf: try decryptor.update(c))
        }

        XCTAssertEqual(metadata, plaintext)
    }
}
