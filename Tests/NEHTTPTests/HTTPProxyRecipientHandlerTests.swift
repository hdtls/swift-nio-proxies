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

final class HTTPProxyRecipientHandlerTests: XCTestCase {

  private var eventLoop: EmbeddedEventLoop!
  private var channel: EmbeddedChannel!
  private var handler: HTTPProxyRecipientHandelr!
  private var passwordReference: String {
    "Basic \(Data("username:password".utf8).base64EncodedString())"
  }

  override func setUp() {
    XCTAssertNil(channel)

    eventLoop = EmbeddedEventLoop()

    handler = HTTPProxyRecipientHandelr(
      passwordReference: passwordReference,
      authenticationRequired: false
    ) { _, _ in
      self.eventLoop.makeSucceededVoidFuture()
    }
    channel = EmbeddedChannel(handler: handler, loop: eventLoop)
  }

  override func tearDown() {
    XCTAssertNotNil(channel)
    channel = nil
    eventLoop = nil
    handler = nil
  }

  func testReceiveDataInInvalidOrderring() throws {
    XCTAssertThrowsError(try channel.writeInbound(HTTPServerRequestPart.end(nil)))
    XCTAssertThrowsError(try channel.finish())

    channel = EmbeddedChannel(handler: handler, loop: eventLoop)
    XCTAssertThrowsError(try channel.writeInbound(HTTPServerRequestPart.body(ByteBuffer())))
    XCTAssertThrowsError(try channel.finish())
  }

  func testProxyAuthenticationRequire() async throws {
    handler = HTTPProxyRecipientHandelr(
      passwordReference: passwordReference,
      authenticationRequired: true
    ) { _,_  in
      self.eventLoop.makeSucceededVoidFuture()
    }
    channel = EmbeddedChannel(handler: handler, loop: eventLoop)

    let head = HTTPRequestHead(version: .http1_1, method: .CONNECT, uri: "example.com")
    try channel.writeInbound(HTTPServerRequestPart.head(head))
    XCTAssertThrowsError(try channel.writeInbound(HTTPServerRequestPart.end(nil))) { error in
      guard case .unacceptableStatusCode(.proxyAuthenticationRequired) = error as? HTTPProxyError
      else {
        XCTFail("should throw HTTPProxyError.unacceptableStatusCode(.proxyAuthenticationRequired)")
        return
      }
    }
    XCTAssertThrowsError(try channel.finish())
  }

  func testProxyAuthenticationWithInvalidUsernameOrPassword() async throws {
    handler = HTTPProxyRecipientHandelr(
      passwordReference: passwordReference,
      authenticationRequired: true
    ) { _,_  in
      self.eventLoop.makeSucceededVoidFuture()
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
      guard case .unacceptableStatusCode(.unauthorized) = error as? HTTPProxyError else {
        XCTFail("should throw HTTPProxyError.unacceptableStatusCode(.unauthorized)")
        return
      }
    }
    XCTAssertThrowsError(try channel.finish())
  }

  func testHTTPConnectProxyWorkflow() async throws {
    let head = HTTPRequestHead.init(version: .http1_1, method: .CONNECT, uri: "example.com")
    try channel.writeInbound(HTTPServerRequestPart.head(head))
    try channel.writeInbound(HTTPServerRequestPart.end(nil))

    let headPart = try channel.readOutbound(as: HTTPServerResponsePart.self)
    let _ = try channel.readOutbound(as: HTTPServerResponsePart.self)
    var headers = HTTPHeaders()
    headers.add(name: "Content-Length", value: "0")
    XCTAssertEqual(headPart, .head(.init(version: .http1_1, status: .ok, headers: headers)))

    XCTAssertThrowsError(try channel.pipeline.handler(type: HTTPProxyRecipientHandelr.self).wait()) {
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
      try channel.pipeline.syncOperations.handler(type: HTTPProxyRecipientHandelr.self)
    ) {
      XCTAssertEqual($0 as? ChannelPipelineError, .notFound)
    }
    XCTAssertNoThrow(try channel.finish())
  }

  func testBufferingBeforePipelineSetupSuccess() async throws {
    let deferPromise = eventLoop.makePromise(of: Void.self)

    handler = HTTPProxyRecipientHandelr(
      passwordReference: "passwordReference",
      authenticationRequired: false
    ) { _, _ in
      deferPromise.futureResult
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

  func testPlainHTTPProxyWorkflow() async throws {
    var headers = HTTPHeaders()
    headers.add(name: "Proxy-Connection", value: "keep-alive")
    let head = HTTPRequestHead.init(version: .http1_1, method: .GET, uri: "http://example.com")
    try channel.writeInbound(HTTPServerRequestPart.head(head))
    try channel.writeInbound(HTTPServerRequestPart.end(nil))

    XCTAssertThrowsError(try channel.pipeline.handler(type: HTTPProxyRecipientHandelr.self).wait()) {
      XCTAssertEqual($0 as? ChannelPipelineError, .notFound)
    }
    XCTAssertNoThrow(try channel.finish())
  }
}
