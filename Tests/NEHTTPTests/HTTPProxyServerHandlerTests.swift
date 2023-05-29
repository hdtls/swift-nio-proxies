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

final class HTTPProxyServerHandlerTests: XCTestCase {

  private var eventLoop: EmbeddedEventLoop!
  private var channel: EmbeddedChannel!
  private var clientChannel: EmbeddedChannel!
  private var handler: HTTPProxyServerHandler!

  override func setUp() {
    XCTAssertNil(channel)
    XCTAssertNil(clientChannel)

    eventLoop = EmbeddedEventLoop()
    clientChannel = EmbeddedChannel(loop: eventLoop)

    let (localGlue, peerGlue) = GlueHandler.matchedPair()

    handler = HTTPProxyServerHandler(
      username: "username",
      passwordReference: "passwordReference",
      authenticationRequired: false
    ) { _ in
      self.channel.pipeline.addHandler(localGlue).flatMap {
        self.clientChannel.pipeline.addHandler(peerGlue)
      }
    }
    channel = EmbeddedChannel(handler: handler, loop: eventLoop)
  }

  override func tearDown() {
    XCTAssertNotNil(channel)
    channel = nil
    clientChannel = nil
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
    handler = HTTPProxyServerHandler(
      username: "username",
      passwordReference: "passwordReference",
      authenticationRequired: true
    ) { _ in
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
    handler = HTTPProxyServerHandler(
      username: "username",
      passwordReference: "passwordReference",
      authenticationRequired: true
    ) { _ in
      self.eventLoop.makeSucceededVoidFuture()
    }
    channel = EmbeddedChannel(handler: handler, loop: eventLoop)

    var headers = HTTPHeaders()
    headers.proxyBasicAuthorization = .init(username: "username", password: "wrong password")
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
    headers.add(name: .contentLength, value: "0")
    XCTAssertEqual(headPart, .head(.init(version: .http1_1, status: .ok, headers: headers)))

    let expected = ByteBuffer(bytes: [1, 2, 3, 4, 5])
    try channel.writeInbound(expected)
    let data = try clientChannel.readOutbound(as: ByteBuffer.self)
    XCTAssertEqual(data, expected)

    try clientChannel.writeInbound(expected)
    XCTAssertEqual(try channel.readOutbound(as: ByteBuffer.self), expected)
    XCTAssertNoThrow(try channel.finish())
  }

  func testHTTPHandlersRemovalWorksAfterPipelineSetupSuccess() async throws {
    let head = HTTPRequestHead.init(version: .http1_1, method: .CONNECT, uri: "example.com")
    try channel.writeInbound(HTTPServerRequestPart.head(head))
    try channel.writeInbound(HTTPServerRequestPart.end(nil))

    XCTAssertNoThrow(try channel.pipeline.syncOperations.handler(type: GlueHandler.self))
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
      try channel.pipeline.syncOperations.handler(type: HTTPProxyServerHandler.self)
    ) {
      XCTAssertEqual($0 as? ChannelPipelineError, .notFound)
    }
    XCTAssertNoThrow(try channel.finish())
  }

  func testBufferingBeforePipelineSetupSuccess() async throws {
    let deferPromise = eventLoop.makePromise(of: Channel.self)

    let (localGlue, peerGlue) = GlueHandler.matchedPair()

    handler = HTTPProxyServerHandler(
      username: "username",
      passwordReference: "passwordReference",
      authenticationRequired: false
    ) { _ in
      deferPromise.futureResult
        .flatMap { clientChannel in
          self.channel.pipeline.addHandler(localGlue).flatMap {
            clientChannel.pipeline.addHandler(peerGlue)
          }
        }
    }
    channel = EmbeddedChannel(handler: handler, loop: eventLoop)

    let head = HTTPRequestHead.init(version: .http1_1, method: .CONNECT, uri: "example.com")
    try channel.writeInbound(HTTPServerRequestPart.head(head))
    try channel.writeInbound(HTTPServerRequestPart.end(nil))

    let expected = ByteBuffer(bytes: [1, 2, 3, 4, 5])
    try channel.writeInbound(expected)

    deferPromise.succeed(clientChannel)

    let data = try clientChannel.readOutbound(as: ByteBuffer.self)

    XCTAssertEqual(data, expected)
    XCTAssertNoThrow(try channel.finish())
  }

  func testPlainHTTPProxyWorkflow() async throws {
    var headers = HTTPHeaders()
    headers.add(name: .proxyConnection, value: "keep-alive")
    let head = HTTPRequestHead.init(version: .http1_1, method: .GET, uri: "http://example.com")
    try channel.writeInbound(HTTPServerRequestPart.head(head))
    try channel.writeInbound(HTTPServerRequestPart.end(nil))

    let expected = ByteBuffer(bytes: [1, 2, 3, 4, 5])
    try clientChannel.writeInbound(expected)
    let data = try channel.readOutbound(as: ByteBuffer.self)
    XCTAssertEqual(data, expected)
    XCTAssertNoThrow(try channel.finish())
  }
}
