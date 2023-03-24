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

import XCTest

@testable import NEVMESS

class VMESSTests: XCTestCase {

  func testGenerateCMDSymmetricKey() throws {
    let result = generateCmdKey(.init(uuidString: "450bae28-b9da-67d0-16bc-4918dc8d79b5")!)
    result.withUnsafeBytes {
      XCTAssertEqual($0.hexString, "da8b7df4396329ebe7a74afc62a9e7c8")
    }
  }

  func testGenerateChaChaPolySymmetricKey() throws {
    let result = try generateChaChaPolySymmetricKey(
      inputKeyMaterial: Data(hexString: "96b727f438a60a07ca1f554ec689862e")
    )
    result.withUnsafeBytes {
      XCTAssertEqual(
        $0.hexString,
        "80c2c504eca628a44855d24e6a9478841d87e34a09027344ebf659d22fb2b88b"
      )
    }
  }

  func testAESCFB128EncryptionWorks() throws {
    let k = "0000000000000000".data(using: .utf8)!
    let i = "8000000000000000".data(using: .utf8)!
    let data = "00000000000000000000000000000000".data(using: .utf8)!
    let expected = "aebe0ec9f0d09b08a0dea6828afc93b3d2487b472cb143aca0307f81e1cd5c9f"

    var result = Array(repeating: UInt8.zero, count: data.count)
    try data.withUnsafeBytes { inPtr in
      try result.withUnsafeMutableBytes { dataOut in
        try commonAESCFB128Encrypt(
          nonce: Array(i),
          key: k,
          dataIn: inPtr,
          dataOut: dataOut,
          dataOutAvailable: data.count
        )
      }
    }

    XCTAssertEqual(result.hexString, expected)
  }

  func testAESECBEncryptionWorks() throws {
    let k = "73941db4cb79371f".data(using: .utf8)!
    let data = "00000000000000000000000000000000".data(using: .utf8)!
    let expected = "edc855576a902fb1613be4b269b3d69d"

    var result = [UInt8](repeating: 0, count: data.count + 16)
    var outLength = 0
    try data.withUnsafeBytes { inPtr in
      try result.withUnsafeMutableBytes { buffer in
        try commonAESEncrypt(
          key: k,
          dataIn: inPtr,
          dataOut: buffer,
          dataOutAvailable: data.count + 16,
          dataOutMoved: &outLength
        )
      }
    }

    XCTAssertEqual(result.prefix(16).hexString, expected)
  }
}
