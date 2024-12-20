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

@testable import NESHAKE128

class SHAKE128Tests: XCTestCase {

  func testSHAKE128Finalize() throws {
    var hasher = SHAKE128.init()
    hasher.update(data: "Yoda said, Do or do not. There is not try.".data(using: .utf8)!)
    XCTAssertEqual(
      hasher.finalize().description.uppercased(),
      "SHAKE128 DIGEST: 0C39568823BBFD6930A596644121AB98"
    )
  }

  func testSHAKE128Read() {
    var hasher = SHAKE128.init()
    hasher.update(data: "Yoda said, Do or do not. There is not try.".data(using: .utf8)!)

    let expected = "SHAKE128 DIGEST: 9244"
    var result: SHAKE128Digest!

    for _ in 0..<1000 {
      result = hasher.read(digestSize: 2)
    }
    XCTAssertEqual(result.description.uppercased(), expected)
  }

  func testSHAKE128CoW() {
    var hf = SHAKE128()
    hf.update(data: [1, 2, 3, 4])

    var hfCopy = hf
    hf.update(data: [5, 6, 7, 8])
    let digest = hf.finalize()

    hfCopy.update(data: [5, 6, 7, 8])
    let copyDigest = hfCopy.finalize()

    XCTAssertEqual(digest, copyDigest)
  }
}
