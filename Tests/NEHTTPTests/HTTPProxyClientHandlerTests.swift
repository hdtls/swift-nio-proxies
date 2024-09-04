//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2021 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NEHTTP
import NIOCore
import NIOEmbedded
import XCTest

class HTTPProxyClientHandlerTests: XCTestCase {

  var channel: EmbeddedChannel!
  var handler: HTTPProxyClientHandler!

  override func setUpWithError() throws {
    XCTAssertNil(self.channel)

    let additionalHTTPHandlers = self.additionalHTTPHandlers

    self.handler = .init(
      passwordReference: "passwordReference",
      authenticationRequired: false,
      destinationAddress: .hostPort(host: "swift.org", port: 443),
      additionalHTTPHandlers: additionalHTTPHandlers,
      timeoutInterval: .seconds(5)
    )

    self.channel = EmbeddedChannel()
    try self.channel.pipeline.syncOperations.addHandlers(additionalHTTPHandlers)
    try self.channel.pipeline.syncOperations.addHandler(handler)
  }

  var additionalHTTPHandlers: [any RemovableChannelHandler] {
    let requestEncoder = HTTPRequestEncoder()
    let responseDecoder = HTTPResponseDecoder()
    return [requestEncoder, ByteToMessageHandler(responseDecoder)]
  }

  override func tearDown() {
    XCTAssertNotNil(self.channel)
    self.channel = nil
  }

  func waitUtilConnected() throws {
    try self.channel.connect(to: .init(ipAddress: "127.0.0.1", port: 80)).wait()
  }

  func testHandshakingShouldBeginAfterChannelActive() throws {
    XCTAssertFalse(channel.isActive)
    XCTAssertNil(try channel.readOutbound())
    try waitUtilConnected()
    XCTAssertTrue(channel.isActive)
    XCTAssertEqual(
      try channel.readOutbound(),
      ByteBuffer(string: "CONNECT swift.org:443 HTTP/1.1\r\n\r\n")
    )
  }

  func testAddHandlerAfterChannelActive() throws {
    //    XCTAssertNoThrow(try self.channel.close().wait())
    //    self.channel = EmbeddedChannel()
    //    XCTAssertNoThrow(try waitUtilConnected())
    //    XCTAssertTrue(self.channel.isActive)
    //    XCTAssertNil(try self.channel.readOutbound())
    //    XCTAssertNoThrow(try channel.pipeline.syncOperations.addHTTPClientHandlers())
    //    XCTAssertNoThrow(self.channel.pipeline.addHandler(self.handler))
    //    XCTAssertEqual(
    //      try channel.readOutbound(),
    //      ByteBuffer(string: "CONNECT swift.org:443 HTTP/1.1\r\n\r\n")
    //    )
    //    XCTAssertNoThrow(try channel.finish())
  }

  func testBuffering() throws {
    try waitUtilConnected()

    let writePromise = self.channel.eventLoop.makePromise(of: Void.self)
    channel.writeAndFlush(ByteBuffer(bytes: [1, 2, 3]), promise: writePromise)
    XCTAssertEqual(
      try channel.readOutbound(),
      ByteBuffer(string: "CONNECT swift.org:443 HTTP/1.1\r\n\r\n")
    )
    try channel.writeInbound(ByteBuffer(string: "HTTP/1.1 200 OK\r\n\r\n"))
    channel.embeddedEventLoop.advanceTime(to: .now())

    XCTAssertNoThrow(try writePromise.futureResult.wait())
    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [1, 2, 3]))
    XCTAssertNoThrow(try channel.finish())
  }

  func testBufferingWithMark() throws {
    try waitUtilConnected()
    let writePromise1 = self.channel.eventLoop.makePromise(of: Void.self)
    let writePromise2 = self.channel.eventLoop.makePromise(of: Void.self)
    channel.write(ByteBuffer(bytes: [1, 2, 3]), promise: writePromise1)
    channel.flush()
    channel.write(ByteBuffer(bytes: [4, 5, 6]), promise: writePromise2)

    XCTAssertEqual(
      try channel.readOutbound(),
      ByteBuffer(string: "CONNECT swift.org:443 HTTP/1.1\r\n\r\n")
    )
    try channel.writeInbound(ByteBuffer(string: "HTTP/1.1 200 OK\r\n\r\n"))
    channel.embeddedEventLoop.advanceTime(to: .now())

    XCTAssertNoThrow(try writePromise1.futureResult.wait())
    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [1, 2, 3]))

    XCTAssertNotNil(try channel.writeAndFlush(ByteBuffer(bytes: [7, 8, 9])).wait())
    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [4, 5, 6]))
    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [7, 8, 9]))
    XCTAssertNoThrow(try channel.finish())
  }

  func testBasicAuthenticationSuccess() throws {
    try channel.close().wait()

    let additionalHTTPHandlers = self.additionalHTTPHandlers

    handler = .init(
      passwordReference: "Basic dXNlcm5hbWU6cGFzc3dvcmRSZWZlcmVuY2U=",
      authenticationRequired: true,
      destinationAddress: .hostPort(host: "swift.org", port: 443),
      additionalHTTPHandlers: additionalHTTPHandlers
    )

    channel = EmbeddedChannel()
    try channel.pipeline.syncOperations.addHandlers(additionalHTTPHandlers)
    try channel.pipeline.syncOperations.addHandler(handler)

    try waitUtilConnected()

    let writePromise = self.channel.eventLoop.makePromise(of: Void.self)
    channel.writeAndFlush(ByteBuffer(bytes: [1, 2, 3]), promise: writePromise)

    XCTAssertEqual(
      try channel.readOutbound(),
      ByteBuffer(
        string:
          "CONNECT swift.org:443 HTTP/1.1\r\nProxy-Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmRSZWZlcmVuY2U=\r\n\r\n"
      )
    )
    try channel.writeInbound(ByteBuffer(string: "HTTP/1.1 200 OK\r\n\r\n"))
    channel.embeddedEventLoop.advanceTime(to: .now())

    XCTAssertNoThrow(try writePromise.futureResult.wait())
    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [1, 2, 3]))
    XCTAssertNoThrow(try channel.finish())
  }

  func testBasicAuthenticationWithIncorrectUsernameOrPassword() throws {
    try channel.close().wait()

    let additionalHTTPHandlers = self.additionalHTTPHandlers
    handler = .init(
      passwordReference: "passwordReference",
      authenticationRequired: true,
      destinationAddress: .hostPort(host: "swift.org", port: 443),
      additionalHTTPHandlers: additionalHTTPHandlers
    )

    channel = EmbeddedChannel()
    try channel.pipeline.syncOperations.addHandlers(additionalHTTPHandlers)
    try channel.pipeline.syncOperations.addHandler(handler)

    try waitUtilConnected()

    XCTAssertEqual(
      try channel.readOutbound(),
      ByteBuffer(
        string:
          "CONNECT swift.org:443 HTTP/1.1\r\nProxy-Authorization: passwordReference\r\n\r\n"
      )
    )
    XCTAssertThrowsError(
      try channel.writeInbound(
        ByteBuffer(string: "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
      )
    )

    XCTAssertThrowsError(try channel.finish())
  }

  func testBasicAuthenticationRequired() throws {
    try waitUtilConnected()

    XCTAssertEqual(
      try channel.readOutbound(),
      ByteBuffer(string: "CONNECT swift.org:443 HTTP/1.1\r\n\r\n")
    )
    XCTAssertThrowsError(
      try channel.writeInbound(
        ByteBuffer(string: "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
      )
    )
    XCTAssertThrowsError(try channel.finish())
  }
}
