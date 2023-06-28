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

@testable import NEHTTPMitM

final class CertificatePoolTests: XCTestCase {

  lazy var pool = try! CertificatePool(base64Encoded: base64String, passphrase: passphrase)

  lazy var base64String: String =
    "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"
  let passphrase = "Y49KEDR7"

  override func setUp() {
    pool.registerKeys([])
    pool.removeAllValues()
  }

  func testInitializeWithWrongPassphrase() {
    XCTAssertThrowsError(
      try CertificatePool(base64Encoded: base64String, passphrase: "wrong passphrase")
    )
  }

  func testInitializeWithInvalidP12String() {
    XCTAssertThrowsError(
      try CertificatePool(base64Encoded: "base64String", passphrase: passphrase)
    )
  }

  func testDelayCertificateCreation() throws {
    pool.registerKeys(["*.swift.org"])
    XCTAssertTrue(pool.isEmpty)
    XCTAssertEqual(pool.keys, ["*.swift.org"])

    pool.registerKeys(["*.swift.org", "swift.org"])
    XCTAssertTrue(pool.isEmpty)
    XCTAssertEqual(pool.keys, ["*.swift.org", "swift.org"])

    _ = try pool.value(forKey: "swift.org")
    XCTAssertEqual(pool.count, 1)
    XCTAssertFalse(pool.isEmpty)

    _ = try pool.value(forKey: "*.swift.org")
    XCTAssertEqual(pool.count, 2)
    XCTAssertFalse(pool.isEmpty)
  }

  func testSetMitMkeys() throws {
    pool.registerKeys(["*.swift.org"])
    XCTAssertTrue(pool.isEmpty)
    XCTAssertEqual(pool.keys, ["*.swift.org"])

    _ = try pool.value(forKey: "*.swift.org")
    XCTAssertEqual(pool.count, 1)
    XCTAssertFalse(pool.isEmpty)

    pool.registerKeys(["*.swift.org", "swift.org"])
    _ = try pool.value(forKey: "swift.org")
    XCTAssertEqual(pool.keys, ["*.swift.org", "swift.org"])
    XCTAssertEqual(pool.count, 2)

    pool.registerKeys(["*.swift.org"])
    XCTAssertEqual(pool.keys, ["*.swift.org"])
    XCTAssertEqual(pool.count, 1)

    pool.registerKeys([])
    XCTAssertEqual(pool.count, 0)
    XCTAssertTrue(pool.isEmpty)
  }

  func testFindCertWithServerHostname() throws {
    var entry = try pool.value(forKey: "swift.org")
    XCTAssertNil(entry)

    pool.registerKeys(["swift.org"])
    entry = try pool.value(forKey: "swift.org")
    XCTAssertNotNil(entry)

    entry = try pool.value(forKey: "*.swift.org")
    XCTAssertNil(entry)
  }

  func testRemoveCacheEntry() throws {
    XCTAssertNil(pool.removeValue(forKey: "swift.org"))
    XCTAssertEqual(pool.count, 0)
    XCTAssertTrue(pool.isEmpty)

    pool.registerKeys(["swift.org"])
    XCTAssertNil(pool.removeValue(forKey: "swift.org"))
    XCTAssertEqual(pool.count, 0)
    XCTAssertTrue(pool.isEmpty)

    _ = try pool.value(forKey: "swift.org")
    XCTAssertNotNil(pool.removeValue(forKey: "swift.org"))
    XCTAssertEqual(pool.count, 0)
    XCTAssertTrue(pool.isEmpty)
    XCTAssertEqual(pool.keys, ["swift.org"])
  }

  func testRemoveAllEntries() throws {
    pool.registerKeys(["swift.org", "*.swift.org"])
    _ = try pool.value(forKey: "swift.org")
    _ = try pool.value(forKey: "*.swift.org")
    pool.removeAllValues()
    XCTAssertEqual(pool.count, 0)
    XCTAssertTrue(pool.isEmpty)
    XCTAssertEqual(pool.keys, ["swift.org", "*.swift.org"])
  }

  let iterations = 10

  func testReadWriteConcurrently() throws {
    pool.registerKeys(Array(0..<iterations).map { "example\($0).com" })
    DispatchQueue.concurrentPerform(iterations: iterations) { i in
      _ = try! pool.value(forKey: "example\(i).com")
    }
    for i in 0..<iterations {
      XCTAssertNotNil(try pool.value(forKey: "example\(i).com"))
    }
    XCTAssertEqual(pool.count, iterations)
    XCTAssertFalse(pool.isEmpty)
  }

  func testRemoveValueConcurrently() throws {
    pool.registerKeys(Array(0..<iterations).map { "\($0)" })
    for i in 0..<iterations {
      _ = try! pool.value(forKey: "example\(i).com")
    }
    DispatchQueue.concurrentPerform(iterations: iterations) { i in
      pool.removeValue(forKey: "example\(i).com")
    }
    XCTAssertTrue(pool.isEmpty)
    XCTAssertEqual(pool.count, 0)
  }
}
