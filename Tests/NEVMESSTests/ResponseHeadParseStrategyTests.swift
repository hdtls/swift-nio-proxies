//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2023 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore
import XCTest

@testable import NEVMESS

final class ResponseHeadParseStrategyTests: XCTestCase {

  func testAuthenticatedHeadParsing() throws {
    let symmetricKey = SymmetricKey(data: Array(hexEncoded: "5c0bf78dbedc7710eee58967a818a17c")!)
    let nonce = Array(hexEncoded: "3237668dc5ece4cb4ddd0fe362f17987")!

    let expected = VMESSResponseHead(
      authenticationCode: 0x3d,
      options: .init(rawValue: 0),
      instructionCode: .init(rawValue: 0),
      instruction: nil
    )

    let parseStrategy = ResponseHeadParseStrategy(
      symmetricKey: symmetricKey,
      nonce: nonce,
      decryptionStrategy: .useAEAD
    )

    let parseInput = ByteBuffer(
      hexEncoded: "f9b53af2a0b7d87ca97fb9f089ba97ed114815ab943557c441cfc86700c4ddd21db3c6c49e7d"
    )!

    guard let (head, consumed) = try parseStrategy.parse(parseInput) else {
      XCTFail()
      return
    }
    XCTAssertEqual(head, expected)
    XCTAssertEqual(consumed, 38)
  }

  func testParseAuthenticatedHeadWithIncompleteEncryptedData() throws {
    let symmetricKey = SymmetricKey(data: Array(hexEncoded: "5c0bf78dbedc7710eee58967a818a17c")!)
    let nonce = Array(hexEncoded: "3237668dc5ece4cb4ddd0fe362f17987")!

    let parseStrategy = ResponseHeadParseStrategy(
      symmetricKey: symmetricKey,
      nonce: nonce,
      decryptionStrategy: .useAEAD
    )

    var parseInput = ByteBuffer()
    // Encrypted length and tag data is missing
    XCTAssertNil(try parseStrategy.parse(parseInput))

    parseInput = ByteBuffer(hexEncoded: "f9b53af2a0")!
    // Encrypted length and tag data is incomplete
    XCTAssertNil(try parseStrategy.parse(parseInput))

    parseInput.writeBytes(Array(hexEncoded: "b7d87ca97fb9f089ba97ed1148")!)
    // Encrypted payload and tag data is missing
    XCTAssertNil(try parseStrategy.parse(parseInput))

    parseInput.writeBytes(Array(hexEncoded: "15ab943557c441cfc86700c4ddd21db3")!)
    // Encrypted payload and tag data is incomplete
    XCTAssertNil(try parseStrategy.parse(parseInput))

    parseInput.writeBytes(Array(hexEncoded: "c6c49e7d")!)
    XCTAssertNotNil(try parseStrategy.parse(parseInput))

    parseInput.clear()

    XCTAssertThrowsError(try parseStrategy._parse(parseInput))

    parseInput.writeInteger(UInt8(0x3d))
    // Missing options data
    XCTAssertThrowsError(try parseStrategy._parse(parseInput))

    parseInput.writeInteger(UInt8.zero)
    // Missing instruction code data
    XCTAssertThrowsError(try parseStrategy._parse(parseInput))

    parseInput.writeInteger(UInt8.zero)
    // Missing instruction length data
    XCTAssertThrowsError(try parseStrategy._parse(parseInput))

    parseInput.writeInteger(UInt8.zero)
    XCTAssertNotNil(try parseStrategy._parse(parseInput))
  }

  func testParseHeadWithIncompleteData() throws {
    let symmetricKey = SymmetricKey(data: Array(hexEncoded: "5c0bf78dbedc7710eee58967a818a17c")!)
    let nonce = Array(hexEncoded: "3237668dc5ece4cb4ddd0fe362f17987")!

    let parseStrategy = ResponseHeadParseStrategy(
      symmetricKey: symmetricKey,
      nonce: nonce,
      decryptionStrategy: .useLegacy
    )

    var parseInput = ByteBuffer()

    // Missing auth code
    XCTAssertNil(try parseStrategy.parse(parseInput))

    parseInput.writeInteger(UInt8(0x3d))
    // Missing options data
    XCTAssertNil(try parseStrategy.parse(parseInput))

    parseInput.writeInteger(UInt8.zero)
    // Missing instruction code data
    XCTAssertNil(try parseStrategy.parse(parseInput))

    parseInput.writeInteger(UInt8.zero)
    // Missing instruction length data
    XCTAssertNil(try parseStrategy.parse(parseInput))

    parseInput.writeInteger(UInt8.zero)
    XCTAssertNotNil(try parseStrategy.parse(parseInput))
  }
}
