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

final class VMESSTypesTests: XCTestCase {

  func testVMESSRequestHead() {
    let v = VMESSVersion.v1
    let u = UUID()
    let authenticationCode = UInt8(1)
    let contentSecurity = ContentSecurity.aes128Gcm
    let options = StreamOptions.chunkStream
    let commandCode = CommandCode.tcp
    let address = NWEndpoint.hostPort(host: "example.com", port: 443)

    let head = VMESSRequestHead(
      user: u,
      authenticationCode: authenticationCode,
      algorithm: contentSecurity,
      options: options,
      commandCode: commandCode,
      address: address
    )

    XCTAssertEqual(head.version, v)
    XCTAssertEqual(head.user, u)
    XCTAssertEqual(head.authenticationCode, authenticationCode)
    XCTAssertEqual(head.contentSecurity, contentSecurity)
    XCTAssertEqual(head.options, options)
    XCTAssertEqual(head.commandCode, commandCode)
    XCTAssertEqual(head.address, address)
  }

  func testVMESSRequestHeadEquatable() {
    let v = VMESSVersion.v1
    let u = UUID()
    let authenticationCode = UInt8(1)
    let contentSecurity = ContentSecurity.aes128Gcm
    let options = StreamOptions.chunkStream
    let commandCode = CommandCode.tcp
    let address = NWEndpoint.hostPort(host: "example.com", port: 443)

    let lhs = VMESSRequestHead(
      version: v,
      user: u,
      authenticationCode: authenticationCode,
      algorithm: contentSecurity,
      options: options,
      commandCode: commandCode,
      address: address
    )

    let rhs = VMESSRequestHead(
      version: v,
      user: u,
      authenticationCode: authenticationCode,
      algorithm: contentSecurity,
      options: options,
      commandCode: commandCode,
      address: address
    )

    XCTAssertEqual(lhs, rhs)
  }

  func testVMESSRequestHeadCoWImplemention() {
    let v = VMESSVersion.v1
    let u = UUID()
    let authenticationCode = UInt8(1)
    let contentSecurity = ContentSecurity.aes128Gcm
    let options = StreamOptions.chunkStream
    let commandCode = CommandCode.tcp
    let address = NWEndpoint.hostPort(host: "example.com", port: 443)

    let head = VMESSRequestHead(
      version: v,
      user: u,
      authenticationCode: authenticationCode,
      algorithm: contentSecurity,
      options: options,
      commandCode: commandCode,
      address: address
    )

    var headCopy = head
    XCTAssertEqual(headCopy, head)

    headCopy.options.insert(.chunkMasking)

    XCTAssertNotEqual(headCopy, head)
  }

  func testVMESSResponseHead() {
    let authenticationCode = UInt8(1)
    let options = StreamOptions.chunkStream
    let code = InstructionCode(rawValue: 0)

    let head = VMESSResponseHead(
      authenticationCode: authenticationCode,
      options: options,
      instructionCode: code,
      instruction: nil
    )

    XCTAssertEqual(head.authenticationCode, authenticationCode)
    XCTAssertEqual(head.options, options)
    XCTAssertEqual(head.instructionCode, code)
    XCTAssertNil(head.instruction)
  }

  func testVMESSResponseHeadEquatable() {
    let authenticationCode = UInt8(1)
    let options = StreamOptions.chunkStream
    let code = InstructionCode(rawValue: 0)

    let lhs = VMESSResponseHead(
      authenticationCode: authenticationCode,
      options: options,
      instructionCode: code,
      instruction: nil
    )

    let rhs = VMESSResponseHead(
      authenticationCode: authenticationCode,
      options: options,
      instructionCode: code,
      instruction: nil
    )

    XCTAssertEqual(lhs, rhs)
  }

  func testVMESSResponseHeadCoWImplemention() {
    let authenticationCode = UInt8(1)
    let options = StreamOptions.chunkStream
    let code = InstructionCode(rawValue: 0)

    let head = VMESSResponseHead(
      authenticationCode: authenticationCode,
      options: options,
      instructionCode: code,
      instruction: nil
    )

    var headCopy = head
    XCTAssertEqual(headCopy, head)

    headCopy.options.insert(.chunkMasking)

    XCTAssertNotEqual(headCopy, head)
  }
}
