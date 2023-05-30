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
import NIOEmbedded
import XCTest

@testable import NEHTTPMitM

final class RecognizerTests: XCTestCase {

  func testTLSSSLRecognitionThatFirstPacketLengthIsLessThanSix() throws {
    let channel = EmbeddedChannel(
      handler: NIOTLSRecognizer { flag, channel in
        XCTAssertFalse(flag)
        return channel.eventLoop.makeSucceededVoidFuture()
      }
    )

    let data = ByteBuffer(bytes: [0x00, 0x01, 0x02, 0x04, 0x0B])
    try channel.writeInbound(data)
    XCTAssertEqual(try channel.readInbound(as: ByteBuffer.self), data)
  }

  func testTLSSSLRecognitionThatRecordTypeIsNotSSL3_RT_HANDSHAKE() throws {
    let channel = EmbeddedChannel(
      handler: NIOTLSRecognizer { flag, channel in
        XCTAssertFalse(flag)
        return channel.eventLoop.makeSucceededVoidFuture()
      }
    )

    let data = ByteBuffer(bytes: [0x00, 0x01, 0x02, 0x04, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x14])
    try channel.writeInbound(data)
    XCTAssertEqual(try channel.readInbound(as: ByteBuffer.self), data)
  }

  func testTLSSSLRecognitionThatHandshakeTypeIsNotUnknowned() throws {
    let channel = EmbeddedChannel(
      handler: NIOTLSRecognizer { flag, channel in
        XCTAssertFalse(flag)
        return channel.eventLoop.makeSucceededVoidFuture()
      }
    )

    let data = ByteBuffer(bytes: [0x16, 0x01, 0x02, 0x04, 0x0B, 0x11])
    try channel.writeInbound(data)
    XCTAssertEqual(try channel.readInbound(as: ByteBuffer.self), data)
  }

  func testTLSSSLRecognition() throws {
    let channel = EmbeddedChannel(
      handler: NIOTLSRecognizer { flag, channel in
        XCTAssertTrue(flag)
        return channel.eventLoop.makeSucceededVoidFuture()
      }
    )

    let data = ByteBuffer(bytes: [0x16, 0x01, 0x02, 0x04, 0x0B, 0x14])
    try channel.writeInbound(data)
    XCTAssertEqual(try channel.readInbound(as: ByteBuffer.self), data)
  }

  func testHTTPRecognitionThatFirstPacketDoseNotContainCRLF() throws {
    let channel = EmbeddedChannel(
      handler: PlainHTTPRecognizer { flag, channel in
        XCTAssertFalse(flag)
        return channel.eventLoop.makeSucceededVoidFuture()
      }
    )

    let data = ByteBuffer(string: "GET /uri HTTP/1.1")
    try channel.writeInbound(data)
    XCTAssertEqual(try channel.readInbound(as: ByteBuffer.self), data)
  }

  func testHTTPRecognitionWhereTheFirstLineOfPacketContainsAnIncorrectNumberOfSpaces() throws {
    var channel = EmbeddedChannel(
      handler: PlainHTTPRecognizer { flag, channel in
        XCTAssertFalse(flag)
        return channel.eventLoop.makeSucceededVoidFuture()
      }
    )

    var data = ByteBuffer(string: "GET/uriHTTP/1.1\r\n")
    try channel.writeInbound(data)
    XCTAssertEqual(try channel.readInbound(as: ByteBuffer.self), data)

    channel = EmbeddedChannel(
      handler: PlainHTTPRecognizer { flag, channel in
        XCTAssertFalse(flag)
        return channel.eventLoop.makeSucceededVoidFuture()
      }
    )

    data = ByteBuffer(string: "GET /uriHTTP/1.1\r\n")
    try channel.writeInbound(data)
    XCTAssertEqual(try channel.readInbound(as: ByteBuffer.self), data)

    channel = EmbeddedChannel(
      handler: PlainHTTPRecognizer { flag, channel in
        XCTAssertFalse(flag)
        return channel.eventLoop.makeSucceededVoidFuture()
      }
    )

    data = ByteBuffer(string: "GET /uri  HTTP/1.1\r\n")
    try channel.writeInbound(data)
    XCTAssertEqual(try channel.readInbound(as: ByteBuffer.self), data)
  }

  func testHTTPRecognitionWhereTheLastComponentOfFirstLineOfPacketDoesNotHasHTTPPrefix() throws {
    let channel = EmbeddedChannel(
      handler: PlainHTTPRecognizer { flag, channel in
        XCTAssertFalse(flag)
        return channel.eventLoop.makeSucceededVoidFuture()
      }
    )

    let data = ByteBuffer(string: "GET /uri ABC/1.1\r\n")
    try channel.writeInbound(data)
    XCTAssertEqual(try channel.readInbound(as: ByteBuffer.self), data)
  }

  func testHTTPRecognition() throws {
    let channel = EmbeddedChannel(
      handler: PlainHTTPRecognizer { flag, channel in
        XCTAssertTrue(flag)
        return channel.eventLoop.makeSucceededVoidFuture()
      }
    )

    let data = ByteBuffer(string: "GET /uri HTTP/1.1\r\n")
    try channel.writeInbound(data)
    XCTAssertEqual(try channel.readInbound(as: ByteBuffer.self), data)
  }
}
