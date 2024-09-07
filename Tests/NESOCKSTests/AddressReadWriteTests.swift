//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2024 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NEAddressProcessing
import NIOCore
import XCTest

@testable import NESOCKS

class AddressReadWriteTests: XCTestCase {

  func testWriteNameHostPort() {
    let expectedAddress: [UInt8] = [
      0x03, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x00, 0x50,
    ]
    var buffer = ByteBuffer()
    let endpoint = Address.hostPort(host: "localhost", port: 80)
    let bytesWritten = buffer.writeEndpointInRFC1928RequestAddressFormat(endpoint)

    XCTAssertEqual(bytesWritten, expectedAddress.count)
    XCTAssertEqual(Array(buffer: buffer), expectedAddress)
  }

  func testWriteIPv4AddressHostPort() {
    let expectedAddress: [UInt8] = [0x01, 0x7F, 0x00, 0x00, 0x01, 0x00, 0x50]
    var buffer = ByteBuffer()
    let address = Address.hostPort(host: "127.0.0.1", port: 80)

    XCTAssertEqual(buffer.writeEndpointInRFC1928RequestAddressFormat(address), 7)
    XCTAssertEqual(buffer.readableBytes, 7)
    XCTAssertEqual(Array(buffer: buffer), expectedAddress)
  }

  func testWriteIPv6AddressHostPort() {
    let expectedAddress: [UInt8] = [
      0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x01, 0x00, 0x50,
    ]
    var buffer = ByteBuffer()
    let address = Address.hostPort(host: "::1", port: 80)

    XCTAssertEqual(buffer.writeEndpointInRFC1928RequestAddressFormat(address), 19)
    XCTAssertEqual(buffer.readableBytes, 19)
    XCTAssertEqual(Array(buffer: buffer), expectedAddress)
  }

  func testReadNameHostPort() throws {
    var buffer = ByteBuffer(bytes: [
      0x03, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x00, 0x50,
    ])
    let endpoint = try buffer.readRFC1928RequestAddressAsEndpoint()
    XCTAssertNotNil(endpoint)
    XCTAssertEqual(endpoint, .hostPort(host: "localhost", port: 80))
    XCTAssertEqual(buffer.readableBytes, 0)
  }

  func testReadIPv4AddressHostPort() throws {
    var buffer = ByteBuffer(bytes: [0x01, 0x7F, 0x00, 0x00, 0x01, 0x00, 0x50])
    let endpoint = try buffer.readRFC1928RequestAddressAsEndpoint()
    XCTAssertNotNil(endpoint)
    XCTAssertEqual(endpoint, .hostPort(host: "127.0.0.1", port: 80))
    XCTAssertEqual(buffer.readableBytes, 0)
  }

  func testReadIPv6AddressHostPort() throws {
    var buffer = ByteBuffer(bytes: [
      0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x01, 0x00, 0x50,
    ])
    let endpoint = try buffer.readRFC1928RequestAddressAsEndpoint()
    XCTAssertNotNil(endpoint)
    XCTAssertEqual(endpoint, .hostPort(host: "::1", port: 80))
    XCTAssertEqual(buffer.readableBytes, 0)
  }

  func testRejectReadFromWrongAddressType() {
    var buffer = ByteBuffer(bytes: [0x02, 0x7F, 0x00, 0x00, 0x01, 0x00, 0x50])
    XCTAssertThrowsError(try buffer.readRFC1928RequestAddressAsEndpoint()) {
      XCTAssertTrue($0 is SocketAddressError)
    }
  }

  func testRejectReadFromIncompleteData() {
    var buffer = ByteBuffer(bytes: [0x01, 0x7F, 0x00])
    XCTAssertNoThrow(XCTAssertNil(try buffer.readRFC1928RequestAddressAsEndpoint()))
  }
}
