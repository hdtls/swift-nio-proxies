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

import NIOCore
import XCTest

@testable import NEVMESS

final class ResponseInstructionParseStrategyTests: XCTestCase {

  func testBasicDynamicPortInstructionParsing() throws {
    let value = ByteBuffer(hexEncoded: "0004d24cfc9664f3815e657f2d72aa8218b1a504008010")!

    let expected = DynamicPortInstruction(
      address: nil,
      port: 1234,
      uid: UUID(uuidString: "4cfc9664-f381-5e65-7f2d-72aa8218b1a5")!,
      level: 128,
      numberOfAlterIDs: 1024,
      effectiveTime: 16
    )

    let instruction = try DynamicPortInstructionParseStrategy().parse(value)
    XCTAssertEqual(instruction, expected)
  }

  func testParseDynamicPortInstructionWithIncompleteData() {
    var value = ByteBuffer(bytes: [])
    XCTAssertThrowsError(try DynamicPortInstructionParseStrategy().parse(value))

    value.writeInteger(UInt8(8))
    value.writeStaticString("test.com")
    // Should throw address parse error
    XCTAssertThrowsError(try DynamicPortInstructionParseStrategy().parse(value))

    value.writeInteger(UInt16(1234))
    value.writeImmutableBuffer(ByteBuffer(hexEncoded: "4cfc9664f3815e657f2d72aa8218b1")!)
    // Missing UUID data
    XCTAssertThrowsError(try DynamicPortInstructionParseStrategy().parse(value))

    value.writeInteger(UInt8(0xa5))
    // Missing number of alter ids data
    XCTAssertThrowsError(try DynamicPortInstructionParseStrategy().parse(value))

    value.writeInteger(UInt16(1024))
    // Missing level data
    XCTAssertThrowsError(try DynamicPortInstructionParseStrategy().parse(value))

    value.writeInteger(UInt8(128))
    // Missing effective time
    XCTAssertThrowsError(try DynamicPortInstructionParseStrategy().parse(value))

    value.writeInteger(UInt8(16))

    let expected = DynamicPortInstruction(
      address: "test.com",
      port: 1234,
      uid: UUID(uuidString: "4cfc9664-f381-5e65-7f2d-72aa8218b1a5")!,
      level: 128,
      numberOfAlterIDs: 1024,
      effectiveTime: 16
    )
    XCTAssertNoThrow(
      XCTAssertEqual(try DynamicPortInstructionParseStrategy().parse(value), expected)
    )
  }

  func testBasicResponseInstructionParsing() throws {
    let value = ByteBuffer(hexEncoded: "de56c8e30004d253b665767706e927b99f57abd2a35aba04008010")!

    let expected = DynamicPortInstruction(
      address: nil,
      port: 1234,
      uid: UUID(uuidString: "53b66576-7706-e927-b99f-57abd2a35aba")!,
      level: 128,
      numberOfAlterIDs: 1024,
      effectiveTime: 16
    )

    let instruction = try ResponseInstructionParseStrategy(instructionCode: 0x01).parse(value)
    XCTAssertEqual(instruction as! DynamicPortInstruction, expected)
  }

  func testParseWithIncopleteData() {
    var value = ByteBuffer()
    XCTAssertThrowsError(try ResponseInstructionParseStrategy(instructionCode: 0x01).parse(value))

    value = ByteBuffer(hexEncoded: "de56c8e30004d253b665767706e927b99f57abd2a35aba040080")!
    // Data validating failed
    XCTAssertThrowsError(try ResponseInstructionParseStrategy(instructionCode: 0x01).parse(value))
  }

  func testParseUnsupportedInstruction() {
    let value = ByteBuffer(hexEncoded: "de56c8e30004d253b665767706e927b99f57abd2a35aba04008010")!
    XCTAssertThrowsError(try ResponseInstructionParseStrategy(instructionCode: 0x02).parse(value))
  }
}
