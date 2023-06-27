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

import NIOEmbedded
import NIOHTTP1
import XCTest

@testable import NEAppEssentials

final class HTTPRequestWriterTests: XCTestCase {

  var channel: EmbeddedChannel!
  var handler: HTTPRequestWriter!

  override func setUpWithError() throws {
    XCTAssertNil(channel)
    handler = .init(host: "example.com", port: 443)
    channel = EmbeddedChannel(handler: handler)
    try channel.connect(to: .init(ipAddress: "127.0.0.1", port: 0)).wait()
  }

  override func tearDown() {
    XCTAssertNotNil(channel)
    XCTAssertNoThrow(XCTAssertTrue(try channel.finish().isClean))
    channel = nil
  }

  func testImmediatelyWriteRequestAfterChannelAdded() throws {
    channel = EmbeddedChannel()
    try channel.connect(to: .init(ipAddress: "127.0.0.1", port: 0)).wait()
    XCTAssertNil(try? channel.readOutbound(as: HTTPClientRequestPart.self))

    XCTAssertNoThrow(try channel.pipeline.syncOperations.addHandler(handler))

    var expected: HTTPClientRequestPart = .head(
      .init(
        version: .http1_1,
        method: .GET,
        uri: "/",
        headers: ["Host": "example.com:443"]
      )
    )
    XCTAssertNoThrow(XCTAssertEqual(try channel.readOutbound(), expected))

    expected = .body(.byteBuffer(ByteBuffer()))
    XCTAssertNoThrow(XCTAssertEqual(try channel.readOutbound(), expected))

    expected = .end(nil)
    XCTAssertNoThrow(XCTAssertEqual(try channel.readOutbound(), expected))
  }

  func testWriteRequestWithBody() throws {
    let body = ByteBuffer(string: "hellow world!")
    handler = HTTPRequestWriter(host: "example.com", port: 443, body: .byteBuffer(body))
    channel = EmbeddedChannel(handler: handler)
    try channel.connect(to: .init(ipAddress: "127.0.0.1", port: 0)).wait()

    var expected: HTTPClientRequestPart = .head(
      .init(
        version: .http1_1,
        method: .GET,
        uri: "/",
        headers: ["Host": "example.com:443", "Content-Length": "\(body.readableBytes)"]
      )
    )
    XCTAssertNoThrow(XCTAssertEqual(try channel.readOutbound(), expected))

    expected = .body(.byteBuffer(body))
    XCTAssertNoThrow(XCTAssertEqual(try channel.readOutbound(), expected))

    expected = .end(nil)
    XCTAssertNoThrow(XCTAssertEqual(try channel.readOutbound(), expected))
  }

  func testWriteRequestWithAdditionalHTTPHeaders() throws {
    handler = HTTPRequestWriter(
      host: "example.com",
      port: 443,
      additionalHTTPHeaders: ["Accept-Encoding": "gzip, deflate"]
    )
    channel = EmbeddedChannel(handler: handler)
    try channel.connect(to: .init(ipAddress: "127.0.0.1", port: 0)).wait()

    var expected: HTTPClientRequestPart = .head(
      .init(
        version: .http1_1,
        method: .GET,
        uri: "/",
        headers: [
          "Host": "example.com:443", "Accept-Encoding": "gzip, deflate",
        ]
      )
    )
    XCTAssertNoThrow(XCTAssertEqual(try channel.readOutbound(), expected))

    expected = .body(.byteBuffer(ByteBuffer()))
    XCTAssertNoThrow(XCTAssertEqual(try channel.readOutbound(), expected))

    expected = .end(nil)
    XCTAssertNoThrow(XCTAssertEqual(try channel.readOutbound(), expected))
  }

  func testCacheWritesUntilHandlerRemoved() {
    // Read client request parts
    XCTAssertNoThrow(try channel.readOutbound(as: HTTPClientRequestPart.self))
    XCTAssertNoThrow(try channel.readOutbound(as: HTTPClientRequestPart.self))
    XCTAssertNoThrow(try channel.readOutbound(as: HTTPClientRequestPart.self))

    channel.writeAndFlush(ByteBuffer(bytes: [0x05, 0x03, 0x11]), promise: nil)
    channel.writeAndFlush(ByteBuffer(bytes: [0x05, 0x02, 0x00]), promise: nil)

    XCTAssertNoThrow(XCTAssertNil(try channel.readOutbound(as: ByteBuffer.self)))

    XCTAssertNoThrow(try channel.pipeline.removeHandler(handler).wait())
    XCTAssertNoThrow(
      XCTAssertEqual(
        try channel.readOutbound(as: ByteBuffer.self),
        ByteBuffer(bytes: [0x05, 0x03, 0x11])
      )
    )
    XCTAssertNoThrow(
      XCTAssertEqual(
        try channel.readOutbound(as: ByteBuffer.self),
        ByteBuffer(bytes: [0x05, 0x02, 0x00])
      )
    )
  }
}
