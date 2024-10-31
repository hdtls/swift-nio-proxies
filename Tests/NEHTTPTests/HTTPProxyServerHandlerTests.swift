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
import NIOEmbedded
import NIOHTTP1
import XCTest

@testable import NEHTTP

final class HTTPProxyServerHandlerTests: XCTestCase {

  private var eventLoop: EmbeddedEventLoop!
  private var channel: EmbeddedChannel!
  private var handler: HTTPProxyServerHandler<Int>!
  private var passwordReference: String {
    "Basic \(Data("username:password".utf8).base64EncodedString())"
  }

  override func setUp() {
    XCTAssertNil(channel)

    eventLoop = EmbeddedEventLoop()

    handler = HTTPProxyServerHandler(
      passwordReference: passwordReference,
      authenticationRequired: false,
      additionalHTTPHandlers: []
    ) { _, _ in
      self.eventLoop.makeSucceededFuture((EmbeddedChannel(), 0))
    }
    channel = EmbeddedChannel(handler: handler, loop: eventLoop)
  }

  override func tearDown() {
    XCTAssertNotNil(channel)
    channel = nil
    eventLoop = nil
    handler = nil
  }

  func testProxyAuthenticationRequire() async throws {
    handler = HTTPProxyServerHandler(
      passwordReference: passwordReference,
      authenticationRequired: true,
      additionalHTTPHandlers: []
    ) { _, _ in
      self.eventLoop.makeSucceededFuture((EmbeddedChannel(), 0))
    }
    channel = EmbeddedChannel(handler: handler, loop: eventLoop)

    let head = HTTPRequestHead(version: .http1_1, method: .CONNECT, uri: "example.com")
    try channel.writeInbound(HTTPServerRequestPart.head(head))
    XCTAssertThrowsError(try channel.writeInbound(HTTPServerRequestPart.end(nil))) { error in
      guard case .proxyAuthenticationRequired = error as? NEHTTPError else {
        XCTFail("should throw NEHTTPError.proxyAuthenticationRequired")
        return
      }
    }
    var response = try XCTUnwrap(channel.readOutbound(as: HTTPServerResponsePart.self))
    XCTAssertEqual(
      response,
      .head(
        .init(
          version: .http1_1,
          status: .proxyAuthenticationRequired,
          headers: ["Connection": "close", "Content-Length": "0"]
        )
      )
    )
    response = try XCTUnwrap(channel.readOutbound(as: HTTPServerResponsePart.self))
    XCTAssertEqual(response, .end(nil))
    XCTAssertNoThrow(try channel.finish(acceptAlreadyClosed: true))
  }

  func testProxyAuthWithInvalidUsernameOrPassword() async throws {
    handler = HTTPProxyServerHandler(
      passwordReference: passwordReference,
      authenticationRequired: true,
      additionalHTTPHandlers: []
    ) { _, _ in
      self.eventLoop.makeSucceededFuture((EmbeddedChannel(), 0))
    }
    channel = EmbeddedChannel(handler: handler, loop: eventLoop)

    var headers = HTTPHeaders()
    headers.replaceOrAdd(name: "Proxy-Authentication", value: "Basic xxxx")
    let head = HTTPRequestHead(
      version: .http1_1,
      method: .CONNECT,
      uri: "example.com",
      headers: headers
    )
    try channel.writeInbound(HTTPServerRequestPart.head(head))
    XCTAssertThrowsError(try channel.writeInbound(HTTPServerRequestPart.end(nil))) { error in
      guard let error = error as? NEHTTPError else {
        XCTFail("should throw NEHTTPError.proxyAuthenticationRequired")
        return
      }
      guard error == .proxyAuthenticationRequired else {
        XCTFail("should throw NEHTTPError.proxyAuthenticationRequired")
        return
      }
    }
    var response = try XCTUnwrap(channel.readOutbound(as: HTTPServerResponsePart.self))
    XCTAssertEqual(
      response,
      .head(
        .init(
          version: .http1_1,
          status: .proxyAuthenticationRequired,
          headers: ["Connection": "close", "Content-Length": "0"]
        )
      )
    )
    response = try XCTUnwrap(channel.readOutbound(as: HTTPServerResponsePart.self))
    XCTAssertEqual(response, .end(nil))
    XCTAssertNoThrow(try channel.finish(acceptAlreadyClosed: true))
  }

  func testHTTPConnectProxyWorkflow() async throws {
    let eventLoop = EmbeddedEventLoop()

    let handler = HTTPProxyServerHandler(
      passwordReference: passwordReference,
      authenticationRequired: false,
      additionalHTTPHandlers: []
    ) { _, _ in
      eventLoop.makeSucceededFuture((EmbeddedChannel(), 0))
    }
    let channel = EmbeddedChannel(handler: handler, loop: eventLoop)

    let head = HTTPRequestHead.init(version: .http1_1, method: .CONNECT, uri: "example.com")
    try channel.writeInbound(HTTPServerRequestPart.head(head))
    try channel.writeInbound(HTTPServerRequestPart.end(nil))

    _ = try await handler.negotiationResultFuture.get()

    let headPart = try channel.readOutbound(as: HTTPServerResponsePart.self)
    let _ = try channel.readOutbound(as: HTTPServerResponsePart.self)
    var headers = HTTPHeaders()
    headers.add(name: "Content-Length", value: "0")
    XCTAssertEqual(headPart, .head(.init(version: .http1_1, status: .ok, headers: headers)))

    XCTAssertThrowsError(
      try channel.pipeline.handler(type: HTTPProxyServerHandler<Int>.self).wait()
    ) {
      XCTAssertEqual($0 as? ChannelPipelineError, .notFound)
    }
    XCTAssertNoThrow(try channel.finish())
  }

  func testHTTPHandlersRemovalWorksAfterPipelineSetupSuccess() async throws {
    let head = HTTPRequestHead.init(version: .http1_1, method: .CONNECT, uri: "example.com")
    try channel.writeInbound(HTTPServerRequestPart.head(head))
    try channel.writeInbound(HTTPServerRequestPart.end(nil))

    XCTAssertThrowsError(
      try channel.pipeline.syncOperations.handler(
        type: ByteToMessageHandler<HTTPRequestDecoder>.self
      )
    ) {
      XCTAssertEqual($0 as? ChannelPipelineError, .notFound)
    }
    XCTAssertThrowsError(
      try channel.pipeline.syncOperations.handler(type: HTTPResponseEncoder.self)
    ) {
      XCTAssertEqual($0 as? ChannelPipelineError, .notFound)
    }
    XCTAssertThrowsError(
      try channel.pipeline.syncOperations.handler(type: HTTPProxyServerHandler<Int>.self)
    ) {
      XCTAssertEqual($0 as? ChannelPipelineError, .notFound)
    }
    XCTAssertNoThrow(try channel.finish())
  }

  func testBufferingBeforePipelineSetupSuccess() async throws {
    let deferPromise = eventLoop.makePromise(of: Void.self)

    handler = HTTPProxyServerHandler(
      passwordReference: "passwordReference",
      authenticationRequired: false,
      additionalHTTPHandlers: []
    ) { _, _ in
      deferPromise.futureResult
        .map { (EmbeddedChannel(), 0) }
    }
    channel = EmbeddedChannel(handler: handler, loop: eventLoop)

    let head = HTTPRequestHead.init(version: .http1_1, method: .CONNECT, uri: "example.com")
    try channel.writeInbound(HTTPServerRequestPart.head(head))
    try channel.writeInbound(HTTPServerRequestPart.end(nil))

    let expected = ByteBuffer(bytes: [1, 2, 3, 4, 5])
    try channel.writeInbound(expected)

    deferPromise.succeed(())

    XCTAssertNoThrow(try channel.finish())
  }

  func testNoAutoHeadersForHEADRequestEncoding() async throws {
    let request = HTTPRequestHead(version: .http1_1, method: .HEAD, uri: "/uri")
    try channel.writeInbound(HTTPServerRequestPart.head(request))
    try channel.writeInbound(HTTPServerRequestPart.end(nil))
    let buffer = try XCTUnwrap(channel.readInbound(as: ByteBuffer.self))
    buffer.assertContainsOnly("HEAD /uri HTTP/1.1\r\n\r\n")
  }

  func testNoAutoHeadersForGetRequestEncoding() throws {
    let request = HTTPRequestHead(version: .http1_1, method: .GET, uri: "/uri")
    try channel.writeInbound(HTTPServerRequestPart.head(request))
    try channel.writeInbound(HTTPServerRequestPart.end(nil))
    let buffer = try XCTUnwrap(channel.readInbound(as: ByteBuffer.self))
    buffer.assertContainsOnly("GET /uri HTTP/1.1\r\n\r\n")
  }

  func testContentLengthHeadersForGETEncoding() throws {
    var request = HTTPRequestHead(version: .http1_1, method: .GET, uri: "/uri")
    let headers = HTTPHeaders([("content-length", "17")])
    request.headers = headers
    try channel.writeInbound(HTTPServerRequestPart.head(request))
    try channel.writeInbound(HTTPServerRequestPart.end(nil))
    let buffer = try XCTUnwrap(channel.readInbound(as: ByteBuffer.self))
    buffer.assertContainsOnly("GET /uri HTTP/1.1\r\ncontent-length: 17\r\n\r\n")
  }

  func testContentLengthHeadersForHEADEncoding() throws {
    var request = HTTPRequestHead(version: .http1_1, method: .HEAD, uri: "/uri")
    let headers = HTTPHeaders([("content-length", "17")])
    request.headers = headers
    try channel.writeInbound(HTTPServerRequestPart.head(request))
    try channel.writeInbound(HTTPServerRequestPart.end(nil))
    let buffer = try XCTUnwrap(channel.readInbound(as: ByteBuffer.self))
    buffer.assertContainsOnly("HEAD /uri HTTP/1.1\r\ncontent-length: 17\r\n\r\n")
  }

  func testNoContentLengthHeadersForTRACE() throws {
    var request = HTTPRequestHead(version: .http1_1, method: .TRACE, uri: "/uri")
    let headers = HTTPHeaders([("content-length", "17")])
    request.headers = headers
    try channel.writeInbound(HTTPServerRequestPart.head(request))
    try channel.writeInbound(HTTPServerRequestPart.end(nil))
    let buffer = try XCTUnwrap(channel.readInbound(as: ByteBuffer.self))
    buffer.assertContainsOnly("TRACE /uri HTTP/1.1\r\n\r\n")
  }

  func testNoTransferEncodingHeadersForTRACE() throws {
    var request = HTTPRequestHead(version: .http1_1, method: .TRACE, uri: "/uri")
    let headers = HTTPHeaders([("transfer-encoding", "chunked")])
    request.headers = headers
    try channel.writeInbound(HTTPServerRequestPart.head(request))
    try channel.writeInbound(HTTPServerRequestPart.end(nil))
    let buffer = try XCTUnwrap(channel.readInbound(as: ByteBuffer.self))
    buffer.assertContainsOnly("TRACE /uri HTTP/1.1\r\n\r\n")
  }

  func testNoChunkedEncodingForHTTP10() throws {
    let request = HTTPRequestHead(version: .http1_0, method: .GET, uri: "/uri")
    try channel.writeInbound(HTTPServerRequestPart.head(request))
    try channel.writeInbound(HTTPServerRequestPart.end(nil))
    var buffer = try XCTUnwrap(channel.readInbound(as: ByteBuffer.self))
    let response = buffer.readString(length: buffer.readableBytes)
    XCTAssertEqual(response, "GET /uri HTTP/1.0\r\n\r\n")
  }

  func testBody() throws {
    var request = HTTPRequestHead(version: .http1_1, method: .POST, uri: "/uri")
    request.headers.add(name: "content-length", value: "4")
    try channel.writeInbound(HTTPServerRequestPart.head(request))
    try channel.writeInbound(HTTPServerRequestPart.body(ByteBuffer(string: "test")))
    try channel.writeInbound(HTTPServerRequestPart.end(nil))
    var buffer = try XCTUnwrap(channel.readInbound(as: ByteBuffer.self))
    buffer.assertContainsOnly("POST /uri HTTP/1.1\r\ncontent-length: 4\r\n\r\n")
    buffer = try XCTUnwrap(channel.readInbound(as: ByteBuffer.self))
    buffer.assertContainsOnly("test")
    buffer = try XCTUnwrap(channel.readInbound(as: ByteBuffer.self))
    buffer.assertContainsOnly("")
  }

  func testPlainHTTPProxyWorkflow() async throws {
    var headers = HTTPHeaders()
    headers.add(name: "Proxy-Connection", value: "keep-alive")
    let head = HTTPRequestHead.init(version: .http1_1, method: .GET, uri: "http://example.com")
    try channel.writeInbound(HTTPServerRequestPart.head(head))
    try channel.writeInbound(HTTPServerRequestPart.end(nil))

    XCTAssertThrowsError(
      try channel.pipeline.handler(type: HTTPProxyServerHandler<Int>.self).wait()
    ) {
      XCTAssertEqual($0 as? ChannelPipelineError, .notFound)
    }
    XCTAssertNoThrow(try channel.finish())
  }
}

extension ByteBuffer {
  fileprivate func assertContainsOnly(_ string: String) {
    let innerData = self.getString(at: self.readerIndex, length: self.readableBytes)!
    XCTAssertEqual(innerData, string)
  }
}
