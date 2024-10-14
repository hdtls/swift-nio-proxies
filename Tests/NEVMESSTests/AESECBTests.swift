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

final class AESECBTests: XCTestCase {

  func testBadKey() {
    let plaintext = "some message".data(using: .utf8)!
    let key = SymmetricKey(size: .bits192)

    XCTAssertThrowsError(try AES.ECB.encrypt(plaintext, using: key))
  }

  func testEncryptDecrypt() throws {
    let k = "73941db4cb79371f".data(using: .utf8)!
    let data = "00000000000000000000000000000000".data(using: .utf8)!
    let expected =
      "edc855576a902fb1613be4b269b3d69dedc855576a902fb1613be4b269b3d69df4031b1bceeef566208b3d013cd30e96"
    XCTAssertEqual(try AES.ECB.encrypt(data, using: .init(data: k)).hexEncodedString(), expected)

    let plaintext = "some secret message".data(using: .utf8)!
    let key = SymmetricKey(size: .bits128)

    let ciphertext = try AES.ECB.encrypt(plaintext, using: key)
    let recoveredPlaintext = try AES.ECB.decrypt(ciphertext, using: key)

    XCTAssertEqual(plaintext, recoveredPlaintext)
  }
}
