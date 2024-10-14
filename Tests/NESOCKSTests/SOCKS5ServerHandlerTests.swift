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

import NIOCore
import NIOEmbedded
import XCTest

@testable import NESOCKS

final class SOCKS5ServerHandlerTests: XCTestCase {

  var eventLoop: EmbeddedEventLoop!
  var channel: EmbeddedChannel!
  var handler: SOCKS5ServerHandler<Int>!

  override func setUpWithError() throws {
    XCTAssertNil(self.channel)

    eventLoop = EmbeddedEventLoop()

    self.handler = SOCKS5ServerHandler(
      username: "",
      passwordReference: "",
      authenticationRequired: false
    ) { _ in
      self.eventLoop.makeSucceededFuture((EmbeddedChannel(), 0))
    }

    self.channel = EmbeddedChannel(handler: self.handler, loop: eventLoop)
    try self.channel.bind(to: .init(ipAddress: "127.0.0.1", port: 0)).wait()
  }

  override func tearDownWithError() throws {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    XCTAssertNotNil(self.channel)
    self.channel = nil
  }

  func testWorkflow() throws {
    XCTAssertNil(try channel.readOutbound())

    try channel.writeInbound(ByteBuffer(bytes: [0x05, 0x01, 0x00]))

    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [0x05, 0x00]))

    try channel.writeInbound(
      ByteBuffer(bytes: [0x05, 0x01, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])
    )

    XCTAssertNotNil(try channel.readOutbound(as: ByteBuffer.self))

    XCTAssertThrowsError(try channel.pipeline.handler(type: SOCKS5ServerHandler<Int>.self).wait()) {
      XCTAssertEqual($0 as? ChannelPipelineError, .notFound)
    }
  }

  func testWorkflowWithUsernamePasswordAuthentication() throws {
    handler = SOCKS5ServerHandler(
      username: "username",
      passwordReference: "passwordReference",
      authenticationRequired: true
    ) { _ in
      self.eventLoop.makeSucceededFuture((EmbeddedChannel(), 0))
    }

    channel = EmbeddedChannel(handler: handler, loop: eventLoop)
    try channel.bind(to: .init(ipAddress: "127.0.0.1", port: 0)).wait()

    XCTAssertNil(try channel.readOutbound())

    try channel.writeInbound(ByteBuffer(bytes: [0x05, 0x01, 0x02]))

    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [0x05, 0x02]))

    let usernameReference = Array("username".data(using: .utf8)!)
    let passwordReference = Array("passwordReference".data(using: .utf8)!)
    let authenticationData =
      [0x01, UInt8(usernameReference.count)] + usernameReference + [
        UInt8(passwordReference.count)
      ] + passwordReference

    try channel.writeInbound(ByteBuffer(bytes: authenticationData))
    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [0x01, 0x00]))

    try channel.writeInbound(
      ByteBuffer(bytes: [0x05, 0x01, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])
    )

    XCTAssertNotNil(try channel.readOutbound())

    XCTAssertThrowsError(try channel.pipeline.handler(type: SOCKS5ServerHandler<Int>.self).wait()) {
      XCTAssertEqual($0 as? ChannelPipelineError, .notFound)
    }
  }

  func testWorkflowWithWrongUsernameOrPasswordAuthentication() throws {
    handler = SOCKS5ServerHandler(
      username: "username",
      passwordReference: "passwordReference",
      authenticationRequired: true
    ) { _ in
      self.eventLoop.makeSucceededFuture((EmbeddedChannel(), 0))
    }

    channel = EmbeddedChannel(handler: handler, loop: eventLoop)
    try channel.bind(to: .init(ipAddress: "127.0.0.1", port: 0)).wait()

    XCTAssertNil(try channel.readOutbound())

    try channel.writeInbound(ByteBuffer(bytes: [0x05, 0x01, 0x02]))

    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [0x05, 0x02]))

    let usernameReference = Array("Wrong credential".data(using: .utf8)!)
    let passwordReference = Array("passwordReference".data(using: .utf8)!)
    let authenticationData =
      [0x01, UInt8(usernameReference.count)] + usernameReference + [
        UInt8(passwordReference.count)
      ] + passwordReference

    try channel.writeInbound(ByteBuffer(bytes: authenticationData))
    XCTAssertEqual(Array(buffer: try channel.readOutbound()!), [0x01, 0x01])
  }

  func testWorkflowDripfeed() throws {
    XCTAssertNil(try channel.readInbound())
    XCTAssertNil(try channel.readOutbound())

    try channel.writeInbound(ByteBuffer(bytes: [0x05]))
    XCTAssertNil(try channel.readOutbound())
    try channel.writeInbound(ByteBuffer(bytes: [0x01, 0x00]))
    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [0x05, 0x00]))

    try channel.writeInbound(ByteBuffer(bytes: [0x05, 0x01, 0x00, 0x01]))
    XCTAssertNil(try channel.readOutbound())
    try channel.writeInbound(ByteBuffer(bytes: [192, 168, 1, 1, 0x00, 0x50]))

    XCTAssertNotNil(try channel.readOutbound())
  }
}
