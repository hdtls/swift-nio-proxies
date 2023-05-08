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
import XCTest

@testable import NEHTTP

extension ByteBuffer {
  fileprivate func assertContainsOnly(_ string: String) {
    let innerData = self.getString(at: self.readerIndex, length: self.readableBytes)!
    XCTAssertEqual(innerData, string)
  }
}

final class PlainHTTPRequestEncoderTests: XCTestCase {

  private func channelRead(method: HTTPMethod, headers: HTTPHeaders) throws -> ByteBuffer {
    let channel = EmbeddedChannel()
    defer {
      XCTAssertEqual(true, try? channel.finish().isClean)
    }

    try channel.pipeline.addHandler(PlainHTTPRequestEncoder()).wait()
    var request = HTTPRequestHead(version: .http1_1, method: method, uri: "/uri")
    request.headers = headers
    try channel.writeInbound(HTTPServerRequestPart.head(request))
    if let buffer = try channel.readInbound(as: ByteBuffer.self) {
      return buffer
    } else {
      fatalError("Could not read ByteBuffer from channel")
    }
  }

  func testNoAutoHeadersForHEAD() throws {
    let writtenData = try channelRead(method: .HEAD, headers: HTTPHeaders())
    writtenData.assertContainsOnly("HEAD /uri HTTP/1.1\r\n\r\n")
  }

  func testNoAutoHeadersForGET() throws {
    let writtenData = try channelRead(method: .GET, headers: HTTPHeaders())
    writtenData.assertContainsOnly("GET /uri HTTP/1.1\r\n\r\n")
  }

  func testGETContentHeadersLeftAlone() throws {
    var headers = HTTPHeaders([("content-length", "17")])
    var writtenData = try channelRead(method: .GET, headers: headers)
    writtenData.assertContainsOnly("GET /uri HTTP/1.1\r\ncontent-length: 17\r\n\r\n")

    headers = HTTPHeaders([("transfer-encoding", "chunked")])
    writtenData = try channelRead(method: .GET, headers: headers)
    writtenData.assertContainsOnly("GET /uri HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n")
  }

  func testContentLengthHeadersForHEAD() throws {
    let headers = HTTPHeaders([("content-length", "0")])
    let writtenData = try channelRead(method: .HEAD, headers: headers)
    writtenData.assertContainsOnly("HEAD /uri HTTP/1.1\r\ncontent-length: 0\r\n\r\n")
  }

  func testTransferEncodingHeadersForHEAD() throws {
    let headers = HTTPHeaders([("transfer-encoding", "chunked")])
    let writtenData = try channelRead(method: .HEAD, headers: headers)
    writtenData.assertContainsOnly("HEAD /uri HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n")
  }

  func testNoContentLengthHeadersForTRACE() throws {
    let headers = HTTPHeaders([("content-length", "0")])
    let writtenData = try channelRead(method: .TRACE, headers: headers)
    writtenData.assertContainsOnly("TRACE /uri HTTP/1.1\r\n\r\n")
  }

  func testNoTransferEncodingHeadersForTRACE() throws {
    let headers = HTTPHeaders([("transfer-encoding", "chunked")])
    let writtenData = try channelRead(method: .TRACE, headers: headers)
    writtenData.assertContainsOnly("TRACE /uri HTTP/1.1\r\n\r\n")
  }

  func testNoChunkedEncodingForHTTP10() throws {
    let channel = EmbeddedChannel()
    defer {
      XCTAssertEqual(true, try? channel.finish().isClean)
    }

    XCTAssertNoThrow(try channel.pipeline.addHandler(PlainHTTPRequestEncoder()).wait())

    // This request contains neither Transfer-Encoding: chunked or Content-Length.
    let request = HTTPRequestHead(version: .http1_0, method: .GET, uri: "/uri")
    XCTAssertNoThrow(try channel.writeInbound(HTTPServerRequestPart.head(request)))
    let writtenData = try channel.readInbound(as: ByteBuffer.self)!
    let writtenResponse = writtenData.getString(
      at: writtenData.readerIndex,
      length: writtenData.readableBytes
    )!
    XCTAssertEqual(writtenResponse, "GET /uri HTTP/1.0\r\n\r\n")
  }

  func testBody() throws {
    let channel = EmbeddedChannel()
    defer {
      XCTAssertEqual(true, try? channel.finish().isClean)
    }

    try channel.pipeline.addHandler(PlainHTTPRequestEncoder()).wait()
    var request = HTTPRequestHead(version: .http1_1, method: .POST, uri: "/uri")
    request.headers.add(name: "content-length", value: "4")

    var buf = channel.allocator.buffer(capacity: 4)
    buf.writeStaticString("test")

    XCTAssertNoThrow(try channel.writeInbound(HTTPServerRequestPart.head(request)))
    XCTAssertNoThrow(try channel.writeInbound(HTTPServerRequestPart.body(buf)))
    XCTAssertNoThrow(try channel.writeInbound(HTTPServerRequestPart.end(nil)))

    assertInbountContainsOnly(channel, "POST /uri HTTP/1.1\r\ncontent-length: 4\r\n\r\n")
    assertInbountContainsOnly(channel, "test")
    assertInbountContainsOnly(channel, "")
  }

  func testCONNECT() throws {
    let channel = EmbeddedChannel()
    defer {
      XCTAssertEqual(true, try? channel.finish().isClean)
    }

    let uri = "server.example.com:80"
    try channel.pipeline.addHandler(PlainHTTPRequestEncoder()).wait()
    var request = HTTPRequestHead(version: .http1_1, method: .CONNECT, uri: uri)
    request.headers.add(name: "Host", value: uri)

    XCTAssertNoThrow(try channel.writeInbound(HTTPServerRequestPart.head(request)))
    XCTAssertNoThrow(try channel.writeInbound(HTTPServerRequestPart.end(nil)))

    assertInbountContainsOnly(channel, "CONNECT \(uri) HTTP/1.1\r\nHost: \(uri)\r\n\r\n")
    assertInbountContainsOnly(channel, "")
  }

  func testChunkedEncodingIsTheDefault() {
    let channel = EmbeddedChannel(handler: PlainHTTPRequestEncoder())
    var buffer = channel.allocator.buffer(capacity: 16)
    var expected = channel.allocator.buffer(capacity: 32)

    XCTAssertNoThrow(
      try channel.writeInbound(
        HTTPServerRequestPart.head(
          .init(
            version: .http1_1,
            method: .POST,
            uri: "/"
          )
        )
      )
    )
    expected.writeString("POST / HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n")
    XCTAssertNoThrow(XCTAssertEqual(expected, try channel.readInbound(as: ByteBuffer.self)))

    buffer.writeString("foo")
    XCTAssertNoThrow(try channel.writeInbound(HTTPServerRequestPart.body(buffer)))

    expected.clear()
    expected.writeString("3\r\n")
    XCTAssertNoThrow(XCTAssertEqual(expected, try channel.readInbound(as: ByteBuffer.self)))
    expected.clear()
    expected.writeString("foo")
    XCTAssertNoThrow(XCTAssertEqual(expected, try channel.readInbound(as: ByteBuffer.self)))
    expected.clear()
    expected.writeString("\r\n")
    XCTAssertNoThrow(XCTAssertEqual(expected, try channel.readInbound(as: ByteBuffer.self)))

    expected.clear()
    expected.writeString("0\r\n\r\n")
    XCTAssertNoThrow(try channel.writeInbound(HTTPServerRequestPart.end(nil)))
    XCTAssertNoThrow(XCTAssertEqual(expected, try channel.readInbound(as: ByteBuffer.self)))

    XCTAssertNoThrow(XCTAssertTrue(try channel.finish().isClean))
  }

  func testChunkedEncodingCanBetEnabled() {
    let channel = EmbeddedChannel(handler: PlainHTTPRequestEncoder())
    var buffer = channel.allocator.buffer(capacity: 16)
    var expected = channel.allocator.buffer(capacity: 32)

    XCTAssertNoThrow(
      try channel.writeInbound(
        HTTPServerRequestPart.head(
          .init(
            version: .http1_1,
            method: .POST,
            uri: "/",
            headers: ["TrAnSfEr-encoding": "chuNKED"]
          )
        )
      )
    )
    expected.writeString("POST / HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n")
    XCTAssertNoThrow(XCTAssertEqual(expected, try channel.readInbound(as: ByteBuffer.self)))

    buffer.writeString("foo")
    XCTAssertNoThrow(try channel.writeInbound(HTTPServerRequestPart.body(buffer)))

    expected.clear()
    expected.writeString("3\r\n")
    XCTAssertNoThrow(XCTAssertEqual(expected, try channel.readInbound(as: ByteBuffer.self)))
    expected.clear()
    expected.writeString("foo")
    XCTAssertNoThrow(XCTAssertEqual(expected, try channel.readInbound(as: ByteBuffer.self)))
    expected.clear()
    expected.writeString("\r\n")
    XCTAssertNoThrow(XCTAssertEqual(expected, try channel.readInbound(as: ByteBuffer.self)))

    expected.clear()
    expected.writeString("0\r\n\r\n")
    XCTAssertNoThrow(try channel.writeInbound(HTTPServerRequestPart.end(nil)))
    XCTAssertNoThrow(XCTAssertEqual(expected, try channel.readInbound(as: ByteBuffer.self)))

    XCTAssertNoThrow(XCTAssertTrue(try channel.finish().isClean))
  }

  func testChunkedEncodingDealsWithZeroLengthChunks() {
    let channel = EmbeddedChannel(handler: PlainHTTPRequestEncoder())
    var buffer = channel.allocator.buffer(capacity: 16)
    var expected = channel.allocator.buffer(capacity: 32)

    XCTAssertNoThrow(
      try channel.writeInbound(
        HTTPServerRequestPart.head(
          .init(
            version: .http1_1,
            method: .POST,
            uri: "/"
          )
        )
      )
    )
    expected.writeString("POST / HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n")
    XCTAssertNoThrow(XCTAssertEqual(expected, try channel.readInbound(as: ByteBuffer.self)))

    buffer.clear()
    XCTAssertNoThrow(try channel.writeInbound(HTTPServerRequestPart.body(buffer)))
    XCTAssertNoThrow(XCTAssertEqual(0, try channel.readInbound(as: ByteBuffer.self)?.readableBytes))

    XCTAssertNoThrow(try channel.writeInbound(HTTPServerRequestPart.end(["foo": "bar"])))

    expected.clear()
    expected.writeString("0\r\nfoo: bar\r\n\r\n")
    XCTAssertNoThrow(XCTAssertEqual(expected, try channel.readInbound(as: ByteBuffer.self)))

    XCTAssertNoThrow(XCTAssertTrue(try channel.finish().isClean))
  }

  func testChunkedEncodingWorksIfNoPromisesAreAttachedToTheWrites() {
    let channel = EmbeddedChannel(handler: PlainHTTPRequestEncoder())
    var buffer = channel.allocator.buffer(capacity: 16)
    var expected = channel.allocator.buffer(capacity: 32)

    channel.pipeline.fireChannelRead(
      NIOAny(
        HTTPServerRequestPart.head(
          .init(
            version: .http1_1,
            method: .POST,
            uri: "/"
          )
        )
      )
    )
    expected.writeString("POST / HTTP/1.1\r\ntransfer-encoding: chunked\r\n\r\n")
    XCTAssertNoThrow(XCTAssertEqual(expected, try channel.readInbound(as: ByteBuffer.self)))

    buffer.writeString("foo")
    channel.pipeline.fireChannelRead(NIOAny(HTTPServerRequestPart.body(buffer)))

    expected.clear()
    expected.writeString("3\r\n")
    XCTAssertNoThrow(XCTAssertEqual(expected, try channel.readInbound(as: ByteBuffer.self)))
    expected.clear()
    expected.writeString("foo")
    XCTAssertNoThrow(XCTAssertEqual(expected, try channel.readInbound(as: ByteBuffer.self)))
    expected.clear()
    expected.writeString("\r\n")
    XCTAssertNoThrow(XCTAssertEqual(expected, try channel.readInbound(as: ByteBuffer.self)))

    expected.clear()
    expected.writeString("0\r\n\r\n")
    channel.pipeline.fireChannelRead(NIOAny(HTTPServerRequestPart.end(nil)))
    XCTAssertNoThrow(XCTAssertEqual(expected, try channel.readInbound(as: ByteBuffer.self)))

    XCTAssertNoThrow(XCTAssertTrue(try channel.finish().isClean))
  }

  private func assertInbountContainsOnly(_ channel: EmbeddedChannel, _ expected: String) {
    XCTAssertNoThrow(
      XCTAssertNotNil(
        try channel.readInbound(as: ByteBuffer.self).map { buffer in
          buffer.assertContainsOnly(expected)
        },
        "couldn't read ByteBuffer"
      )
    )
  }
}
