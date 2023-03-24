//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2022 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import XCTest

@testable import NEVMESS

class KDFTests: XCTestCase {

  func testDeriveKey() {
    let symmetricKey = SymmetricKey(data: "Demo Key for KDF Value Test".data(using: .utf8)!)
    let expectedKey = "53e9d7e1bd7bd25022b71ead07d8a596efc8a845c7888652fd684b4903dc8892"

    let result = KDF.deriveKey(
      inputKeyMaterial: symmetricKey,
      info: [
        Array("Demo Path for KDF Value Test".utf8),
        Array("Demo Path for KDF Value Test2".utf8),
        Array("Demo Path for KDF Value Test3".utf8),
      ]
    )
    result.withUnsafeBytes {
      XCTAssertEqual($0.hexString, expectedKey)
    }
  }
}
