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

class VMESSTests: XCTestCase {

  func testGenerateCMDSymmetricKey() throws {
    let result = generateCmdKey(.init(uuidString: "450bae28-b9da-67d0-16bc-4918dc8d79b5")!)
    result.withUnsafeBytes {
      XCTAssertEqual($0.hexEncodedString(), "da8b7df4396329ebe7a74afc62a9e7c8")
    }
  }

  func testGenerateChaChaPolySymmetricKey() throws {
    let result = generateChaChaPolySymmetricKey(
      inputKeyMaterial: .init(data: Data(hexEncoded: "96b727f438a60a07ca1f554ec689862e")!)
    )
    result.withUnsafeBytes {
      XCTAssertEqual(
        $0.hexEncodedString(),
        "80c2c504eca628a44855d24e6a9478841d87e34a09027344ebf659d22fb2b88b"
      )
    }
  }
}
