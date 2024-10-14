//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2022 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import XCTest

@testable import NEVMESS

final class AESCFB128Tests: XCTestCase {

  func testBadKey() {
    let plaintext = Data("some message".utf8)
    let key = SymmetricKey(size: .bits192)
    let nonce = AES.CFB.Nonce()

    XCTAssertThrowsError(try AES.CFB.encrypt(plaintext, using: key, nonce: nonce))
  }

  func testEncryptDecrypt() throws {
    let k = SymmetricKey(data: Data("0000000000000000".utf8))
    let i = try AES.CFB.Nonce(data: Data("8000000000000000".utf8))
    let data = "00000000000000000000000000000000".data(using: .utf8)!
    let expected = "aebe0ec9f0d09b08a0dea6828afc93b3d2487b472cb143aca0307f81e1cd5c9f"
    XCTAssertEqual(try AES.CFB.encrypt(data, using: k, nonce: i).hexEncodedString(), expected)

    let plaintext = Data("some secret message".utf8)
    let key = SymmetricKey(size: .bits128)
    let nonce = AES.CFB.Nonce()
    let ciphertext = try AES.CFB.encrypt(plaintext, using: key, nonce: nonce)
    let recoveredPlaintext = try AES.CFB.decrypt(ciphertext, using: key, nonce: nonce)
    XCTAssertEqual(plaintext, recoveredPlaintext)
  }
}
