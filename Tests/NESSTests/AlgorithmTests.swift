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

@testable import NESS

final class AlgorithmTests: XCTestCase {

  func testCreateAES128GCMALGOWithRawValue() throws {
    var rawValue = "aes-128-gcm"
    var algo = Algorithm(rawValue: rawValue)
    XCTAssertEqual(algo, .aes128Gcm)

    rawValue = "aes-128-gCM"
    algo = Algorithm(rawValue: rawValue)
    XCTAssertEqual(algo, .aes128Gcm)

    rawValue = "AES-128-GCM"
    algo = Algorithm(rawValue: rawValue)
    XCTAssertEqual(algo, .aes128Gcm)

    XCTAssertEqual(Algorithm.aes128Gcm.rawValue, "AES-128-GCM")
  }

  func testCreateAES128GCMWithUnmatchedRawValue() {
    var rawValue = "ae-128-gcm"
    var algo = Algorithm(rawValue: rawValue)
    XCTAssertNil(algo)

    rawValue = "aes-gcm"
    algo = Algorithm(rawValue: rawValue)
    XCTAssertNil(algo)
  }

  func testCreateAES256GCMALGOWithRawValue() throws {
    var rawValue = "aes-256-gcm"
    var algo = Algorithm(rawValue: rawValue)
    XCTAssertEqual(algo, .aes256Gcm)

    rawValue = "aes-256-gCM"
    algo = Algorithm(rawValue: rawValue)
    XCTAssertEqual(algo, .aes256Gcm)

    rawValue = "AES-256-GCM"
    algo = Algorithm(rawValue: rawValue)
    XCTAssertEqual(algo, .aes256Gcm)

    XCTAssertEqual(Algorithm.aes256Gcm.rawValue, "AES-256-GCM")
  }

  func testCreateAES256GCMWithUnmatchedRawValue() {
    var rawValue = "ae-256-gcm"
    var algo = Algorithm(rawValue: rawValue)
    XCTAssertNil(algo)

    rawValue = "aes-gcm"
    algo = Algorithm(rawValue: rawValue)
    XCTAssertNil(algo)
  }

  func testCreateChaCha20Poly1305ALGOWithRawValue() {
    var rawValue = "CHACHA20-POLY1305"
    var algo = Algorithm(rawValue: rawValue)
    XCTAssertEqual(algo, .chaCha20Poly1305)

    rawValue = "chacha20-poly1305"
    algo = Algorithm(rawValue: rawValue)
    XCTAssertEqual(algo, .chaCha20Poly1305)

    rawValue = "ChaCha20-Poly1305"
    algo = Algorithm(rawValue: rawValue)
    XCTAssertEqual(algo, .chaCha20Poly1305)

    XCTAssertEqual(Algorithm.chaCha20Poly1305.rawValue, "ChaCha20-Poly1305")
  }

  func testCreateChaCha20Poly1305WithUnmatchedRawValue() {
    var rawValue = "ChaCha-Poly1305"
    var algo = Algorithm(rawValue: rawValue)
    XCTAssertNil(algo)

    rawValue = "chach20poly1305"
    algo = Algorithm(rawValue: rawValue)
    XCTAssertNil(algo)
  }
}
