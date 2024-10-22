//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2021 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import HTTPTypes
import NEHTTP
import NIOCore
import NIOEmbedded
import NIOHTTP1
import NIOHTTPTypes
import XCTest

class HTTPProxyClientHandlerTests: XCTestCase {

  private func makeHandler() -> HTTPProxyClientHandler {
    HTTPProxyClientHandler(
      passwordReference: "Basic dXNlcm5hbWU6cGFzc3dvcmRSZWZlcmVuY2U=",
      authenticationRequired: false,
      destinationAddress: .hostPort(host: "example.com", port: 443),
      additionalHTTPHandlers: [],
      timeoutInterval: .seconds(5)
    )
  }

  private func assertThrowsError(_ future: EventLoopFuture<Void>?) async {
    let expectation = expectation(description: "Wait negotiation result")
    if let future {
      future.whenComplete { result in
        do {
          try result.get()
          XCTFail("should fail with AbortError")
        } catch {
        }
        expectation.fulfill()
      }
    } else {
      expectation.fulfill()
    }
    await fulfillment(of: [expectation], timeout: 5, enforceOrder: false)
  }

  func testNegotiationResultFutureAvailableAfterHanderAdded() async throws {
    let channel = EmbeddedChannel()
    let handler = makeHandler()
    XCTAssertNil(handler.negotiationResultFuture)
    try await channel.pipeline.addHandler(handler).get()
    XCTAssertNotNil(handler.negotiationResultFuture)
  }

  func testRemoveHandlerBeforeResponseHeadReceived() async throws {
    let channel = EmbeddedChannel()
    let handler = makeHandler()
    try await channel.pipeline.addHandler(handler).get()
    channel.pipeline.removeHandler(handler, promise: nil)
    await assertThrowsError(handler.negotiationResultFuture)
    XCTAssertThrowsError(try channel.finish())
  }

  func testRemoveHandlerBeforeResponseReceived() async throws {
    let channel = EmbeddedChannel()
    let handler = makeHandler()
    try await channel.pipeline.addHandler(handler).get()
    try channel.writeInbound(HTTPResponsePart.head(.init(status: .ok)))
    channel.pipeline.removeHandler(handler, promise: nil)
    await assertThrowsError(handler.negotiationResultFuture)
    XCTAssertThrowsError(try channel.finish())
  }

  func testHandshakingShouldBeginImmediatelyAfterChannelAdded() async throws {
    let channel = EmbeddedChannel()
    try await channel.pipeline.addHandler(makeHandler()).get()
    XCTAssertEqual(
      try channel.readOutbound(),
      HTTPRequestPart.head(
        .init(method: .connect, scheme: nil, authority: "example.com:443", path: nil))
    )
  }

  func testIgnoreDuplicatedHandshakeRequestAfterHandlerActive() async throws {
    let channel = EmbeddedChannel()
    try await channel.pipeline.addHandler(makeHandler()).get()
    XCTAssertFalse(channel.isActive)
    XCTAssertNotNil(try channel.readOutbound(as: HTTPRequestPart.self))
    XCTAssertNotNil(try channel.readOutbound(as: HTTPRequestPart.self))
    XCTAssertNil(try channel.readOutbound(as: HTTPRequestPart.self))

    try channel.connect(to: .init(ipAddress: "0.0.0.0", port: 0), promise: nil)
    XCTAssertTrue(channel.isActive)
    XCTAssertNil(try channel.readOutbound(as: HTTPRequestPart.self))
  }

  func testHandshakeWithoutAuthentication() async throws {
    let channel = EmbeddedChannel()
    let handler = makeHandler()
    try await channel.pipeline.addHandler(handler).get()

    XCTAssertEqual(
      try channel.readOutbound(as: HTTPRequestPart.self),
      .head(.init(method: .connect, scheme: nil, authority: "example.com:443", path: nil)))
  }

  func testHandshakeWithAuthentication() async throws {
    let channel = EmbeddedChannel()
    let handler = HTTPProxyClientHandler(
      passwordReference: "Basic dXNlcm5hbWU6cGFzc3dvcmRSZWZlcmVuY2U=",
      authenticationRequired: true,
      destinationAddress: .hostPort(host: "example.com", port: 443),
      additionalHTTPHandlers: [],
      timeoutInterval: .seconds(5)
    )
    try await channel.pipeline.addHandler(handler).get()

    XCTAssertEqual(
      try channel.readOutbound(as: HTTPRequestPart.self),
      .head(
        .init(
          method: .connect, scheme: nil, authority: "example.com:443", path: nil,
          headerFields: [.proxyAuthorization: "Basic dXNlcm5hbWU6cGFzc3dvcmRSZWZlcmVuY2U="])))
  }

  func testReceiveProxyAuthenticationRequiredResponse() async throws {
    let channel = EmbeddedChannel()
    let handler = makeHandler()
    try await channel.pipeline.addHandler(handler).get()

    XCTAssertEqual(
      try channel.readOutbound(),
      HTTPRequestPart.head(
        .init(method: .connect, scheme: nil, authority: "example.com:443", path: nil))
    )

    XCTAssertThrowsError(
      try channel.writeInbound(HTTPResponsePart.head(.init(status: .proxyAuthenticationRequired)))
    )
    await assertThrowsError(handler.negotiationResultFuture)
    XCTAssertThrowsError(try channel.finish())
  }

  func testReceiveResponseThatIsNotSuccessfulOrProxyAuthenticationRequiredResponse() async throws {
    let channel = EmbeddedChannel()
    let handler = makeHandler()
    try await channel.pipeline.addHandler(handler).get()
    XCTAssertThrowsError(
      try channel.writeInbound(HTTPResponsePart.head(.init(status: .internalServerError)))
    )
    await assertThrowsError(handler.negotiationResultFuture)
    XCTAssertThrowsError(try channel.finish())
  }

  func testFailedAfterHTTPBodyReceived() async throws {
    let channel = EmbeddedChannel()
    let handler = makeHandler()
    try await channel.pipeline.addHandler(handler).get()
    try channel.writeInbound(HTTPResponsePart.head(.init(status: .ok)))
    XCTAssertThrowsError(try channel.writeInbound(HTTPResponsePart.body(.init(bytes: [0x01]))))
    try channel.writeInbound(HTTPResponsePart.end(nil))
    await assertThrowsError(handler.negotiationResultFuture)
    XCTAssertThrowsError(try channel.finish())
  }

  func testFailedToRemoveAdditionalHTTPHandlers() async throws {
    let channel = EmbeddedChannel()
    class ExtraHandler: ChannelInboundHandler, RemovableChannelHandler {
      typealias InboundIn = NIOAny
    }
    let handler = HTTPProxyClientHandler(
      passwordReference: "",
      authenticationRequired: false,
      destinationAddress: .hostPort(host: "example.com", port: 443),
      additionalHTTPHandlers: [
        ExtraHandler()
      ]
    )
    try await channel.pipeline.addHandler(handler).get()
    try channel.writeInbound(HTTPResponsePart.head(.init(status: .ok)))
    XCTAssertThrowsError(try channel.writeInbound(HTTPResponsePart.end(nil)))
    await assertThrowsError(handler.negotiationResultFuture)
    XCTAssertThrowsError(try channel.finish())
  }

  func testBufferAllWritesBeforeHandshakeComplete() async throws {
    let channel = EmbeddedChannel()
    try await channel.pipeline.addHandler(makeHandler()).get()

    channel.writeAndFlush(ByteBuffer(bytes: [1, 2, 3]), promise: nil)

    try channel.writeInbound(HTTPResponsePart.head(.init(status: .ok)))
    try channel.writeInbound(HTTPResponsePart.end(nil))

    _ = try channel.readOutbound(as: HTTPRequestPart.self)
    _ = try channel.readOutbound(as: HTTPRequestPart.self)

    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [1, 2, 3]))
    XCTAssertNoThrow(try channel.finish())
  }

  func testBufferingWithMark() async throws {
    let channel = EmbeddedChannel()
    try await channel.pipeline.addHandler(makeHandler()).get()

    channel.write(ByteBuffer(bytes: [1, 2, 3]), promise: nil)
    channel.flush()
    channel.write(ByteBuffer(bytes: [4, 5, 6]), promise: nil)

    try channel.writeInbound(HTTPResponsePart.head(.init(status: .ok)))
    try channel.writeInbound(HTTPResponsePart.end(nil))

    _ = try channel.readOutbound(as: HTTPRequestPart.self)
    _ = try channel.readOutbound(as: HTTPRequestPart.self)

    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [1, 2, 3]))

    XCTAssertNotNil(try channel.writeAndFlush(ByteBuffer(bytes: [7, 8, 9])).wait())
    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [4, 5, 6]))
    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [7, 8, 9]))
    XCTAssertNoThrow(try channel.finish())
  }

  func testTimeoutAfterHeadReceived() async throws {
    let channel = EmbeddedChannel()
    let handler = HTTPProxyClientHandler(
      passwordReference: "Basic dXNlcm5hbWU6cGFzc3dvcmRSZWZlcmVuY2U=",
      authenticationRequired: false,
      destinationAddress: .hostPort(host: "example.com", port: 443),
      additionalHTTPHandlers: [],
      timeoutInterval: .seconds(1)
    )
    try await channel.pipeline.addHandler(handler).get()

    _ = try channel.readOutbound(as: HTTPRequestPart.self)
    _ = try channel.readOutbound(as: HTTPRequestPart.self)

    try channel.writeInbound(HTTPResponsePart.head(.init(status: .ok)))

    try await Task.sleep(nanoseconds: 1_000_000_000)

    _ = try channel.readInbound(as: HTTPResponsePart.self)

    XCTAssertThrowsError(try channel.finish())
  }
}
