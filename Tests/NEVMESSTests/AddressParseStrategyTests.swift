//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2023 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NEMisc
import XCTest

@testable import NEVMESS

final class AddressParseStrategyTests: XCTestCase {

  func testBasicParsing() throws {
    var parseInput = ByteBuffer(integer: UInt8(11))
    parseInput.writeStaticString("192.168.0.1")
    parseInput.writeInteger(UInt16(80))
    var expectedParseOut = ("192.168.0.1", 80)
    var parsedAddress = try AddressParseStrategy().parse(parseInput)
    XCTAssertEqual(parsedAddress.address, expectedParseOut.0)
    XCTAssertEqual(parsedAddress.port, expectedParseOut.1)

    parseInput.clear()
    parseInput.writeInteger(UInt8(8))
    parseInput.writeStaticString("test.com")
    parseInput.writeInteger(UInt16(443))
    expectedParseOut = ("test.com", 443)
    parsedAddress = try AddressParseStrategy().parse(parseInput)
    XCTAssertEqual(parsedAddress.address, expectedParseOut.0)
    XCTAssertEqual(parsedAddress.port, expectedParseOut.1)
  }

  func testParseWithIncompleteData() {
    var parseInput = ByteBuffer()
    XCTAssertThrowsError(try AddressParseStrategy().parse(parseInput))

    parseInput.writeInteger(UInt8.zero)
    // Port should be two bytes
    parseInput.writeInteger(UInt8(80))
    XCTAssertThrowsError(try AddressParseStrategy().parse(parseInput))

    parseInput.clear()
    parseInput.writeInteger(UInt8(8))
    parseInput.writeStaticString("test.co")
    XCTAssertThrowsError(try AddressParseStrategy().parse(parseInput))

    parseInput.clear()
    parseInput.writeInteger(UInt8(8))
    parseInput.writeStaticString("test.com")
    parseInput.writeInteger(UInt8(80))
    XCTAssertThrowsError(try AddressParseStrategy().parse(parseInput))
  }
}
