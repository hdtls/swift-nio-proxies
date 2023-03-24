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

import NIOEmbedded
import XCTest

@testable import NESOCKS

class SOCKS5ClientHandlerTests: XCTestCase {

  var channel: EmbeddedChannel!
  var handler: SOCKS5ClientHandler!

  override func setUp() {
    XCTAssertNil(self.channel)
    self.handler = SOCKS5ClientHandler(
      username: "",
      passwordReference: "",
      authenticationRequired: false,
      destinationAddress: .socketAddress(try! .init(ipAddress: "192.168.1.1", port: 80))
    )
    self.channel = EmbeddedChannel(handler: self.handler)
  }

  func waitUntilConnected() throws {
    try self.channel.connect(to: .init(ipAddress: "127.0.0.1", port: 80)).wait()
  }

  override func tearDown() {
    XCTAssertNotNil(self.channel)
    self.channel = nil
  }

  func testWorkflow() throws {
    try waitUntilConnected()

    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [0x05, 0x01, 0x00]))
    try channel.writeInbound(ByteBuffer(bytes: [0x05, 0x00]))
    XCTAssertEqual(
      try channel.readOutbound(),
      ByteBuffer(bytes: [0x05, 0x01, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])
    )
    try channel.writeInbound(
      ByteBuffer(bytes: [0x05, 0x00, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])
    )
    try self.channel.writeInbound(ByteBuffer(bytes: [1, 2, 3, 4, 5]))
    XCTAssertEqual(try channel.readInbound(), ByteBuffer(bytes: [1, 2, 3, 4, 5]))
  }

  func testWorkflowWithUsernamePasswordAuthentication() throws {
    let handler = SOCKS5ClientHandler(
      username: "username",
      passwordReference: "passwordReference",
      authenticationRequired: true,
      destinationAddress: .socketAddress(try! .init(ipAddress: "192.168.1.1", port: 80))
    )
    XCTAssertNoThrow(try channel.finish())
    channel = nil
    channel = EmbeddedChannel(handler: handler)

    try waitUntilConnected()

    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [0x05, 0x01, 0x02]))

    try channel.writeInbound(ByteBuffer(bytes: [0x05, 0x02]))

    let usernameReference = Array("username".data(using: .utf8)!)
    let passwordReference = Array("passwordReference".data(using: .utf8)!)
    let authenticationData =
      [0x01, UInt8(usernameReference.count)] + usernameReference + [
        UInt8(passwordReference.count)
      ] + passwordReference
    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: authenticationData))

    try channel.writeInbound(ByteBuffer(bytes: [0x01, 0x00]))

    XCTAssertEqual(
      try channel.readOutbound(),
      ByteBuffer(bytes: [0x05, 0x01, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])
    )

    // server replies yay
    try channel.writeInbound(
      ByteBuffer(bytes: [0x05, 0x00, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])
    )
  }

  func testWorkflowWithWrongUsernameOrPasswordAuthentication() throws {
    let handler = SOCKS5ClientHandler(
      username: "username",
      passwordReference: "passwordReference",
      authenticationRequired: true,
      destinationAddress: .socketAddress(try! .init(ipAddress: "192.168.1.1", port: 80))
    )
    XCTAssertNoThrow(try channel.finish())
    channel = nil
    channel = EmbeddedChannel(handler: handler)

    try waitUntilConnected()

    // the client should start the handshake instantly
    let bytes: [UInt8] = [0x05, 0x01, 0x02]
    if var buffer = try channel.readOutbound(as: ByteBuffer.self) {
      XCTAssertEqual(buffer.readBytes(length: buffer.readableBytes), bytes)
    } else if bytes.count > 0 {
      XCTFail("Expected bytes but found none")
    }

    try channel.writeInbound(ByteBuffer(bytes: [0x05, 0x02]))

    let usernameReference = Array("username".data(using: .utf8)!)
    let passwordReference = Array("passwordReference".data(using: .utf8)!)
    let authenticationData =
      [0x01, UInt8(usernameReference.count)] + usernameReference + [
        UInt8(passwordReference.count)
      ] + passwordReference
    if var buffer = try channel.readOutbound(as: ByteBuffer.self) {
      XCTAssertEqual(buffer.readBytes(length: buffer.readableBytes), authenticationData)
    } else if authenticationData.count > 0 {
      XCTFail("Expected bytes but found none")
    }

    XCTAssertThrowsError(try channel.writeInbound(ByteBuffer(bytes: [0x01, 0x01])))
    XCTAssertThrowsError(try channel.finish()) { error in
      XCTAssertEqual(error as? ChannelError, .alreadyClosed)
    }
  }

  func testWorkflowDripfeed() throws {
    try waitUntilConnected()

    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [0x05, 0x01, 0x00]))

    try self.channel.writeInbound(ByteBuffer(bytes: [0x05]))
    XCTAssertNil(try channel.readOutbound())
    try self.channel.writeInbound(ByteBuffer(bytes: [0x00]))
    XCTAssertEqual(
      try channel.readOutbound(),
      ByteBuffer(bytes: [0x05, 0x01, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])
    )

    // drip feed server response
    try self.channel.writeInbound(ByteBuffer(bytes: [0x05, 0x00, 0x00, 0x01]))
    XCTAssertNil(try channel.readOutbound())
    try self.channel.writeInbound(ByteBuffer(bytes: [192, 168]))
    XCTAssertNil(try channel.readOutbound())
    try self.channel.writeInbound(ByteBuffer(bytes: [1, 1]))
    XCTAssertNil(try channel.readOutbound())
    try self.channel.writeInbound(ByteBuffer(bytes: [0x00, 0x50]))

    // any inbound data should now go straight through
    try self.channel.writeInbound(ByteBuffer(bytes: [1, 2, 3, 4, 5]))
    XCTAssertEqual(try channel.readInbound(), ByteBuffer(bytes: [1, 2, 3, 4, 5]))
  }

  func testBuffering() throws {
    try waitUntilConnected()

    let writePromise = self.channel.eventLoop.makePromise(of: Void.self)
    self.channel.writeAndFlush(ByteBuffer(bytes: [1, 2, 3, 4, 5]), promise: writePromise)
    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [0x05, 0x01, 0x00]))
    try self.channel.writeInbound(ByteBuffer(bytes: [0x05, 0x00]))
    XCTAssertEqual(
      try channel.readOutbound(),
      ByteBuffer(bytes: [0x05, 0x01, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])
    )
    try self.channel.writeInbound(
      ByteBuffer(bytes: [0x05, 0x00, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])
    )

    XCTAssertNoThrow(try writePromise.futureResult.wait())
    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [1, 2, 3, 4, 5]))
  }

  func testBufferingWithMark() throws {
    try waitUntilConnected()

    let writePromise1 = self.channel.eventLoop.makePromise(of: Void.self)
    let writePromise2 = self.channel.eventLoop.makePromise(of: Void.self)
    self.channel.write(ByteBuffer(bytes: [1, 2, 3]), promise: writePromise1)
    self.channel.flush()
    self.channel.write(ByteBuffer(bytes: [4, 5, 6]), promise: writePromise2)

    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [0x05, 0x01, 0x00]))
    try self.channel.writeInbound(ByteBuffer(bytes: [0x05, 0x00]))
    XCTAssertEqual(
      try channel.readOutbound(),
      ByteBuffer(bytes: [0x05, 0x01, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])
    )
    try self.channel.writeInbound(
      ByteBuffer(bytes: [0x05, 0x00, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])
    )

    XCTAssertNoThrow(try writePromise1.futureResult.wait())
    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [1, 2, 3]))

    XCTAssertNoThrow(try self.channel.writeAndFlush(ByteBuffer(bytes: [7, 8, 9])).wait())
    XCTAssertNoThrow(try writePromise2.futureResult.wait())
    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [4, 5, 6]))
    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [7, 8, 9]))
  }

  func testProxyConnectionFailed() throws {
    try waitUntilConnected()

    class ErrorHandler: ChannelInboundHandler {
      typealias InboundIn = ByteBuffer

      var promise: EventLoopPromise<Void>

      init(promise: EventLoopPromise<Void>) {
        self.promise = promise
      }

      func errorCaught(context: ChannelHandlerContext, error: Error) {
        promise.fail(error)
      }
    }

    // start handshake, send request
    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [0x05, 0x01, 0x00]))
    try self.channel.writeInbound(ByteBuffer(bytes: [0x05, 0x00]))
    XCTAssertEqual(
      try channel.readOutbound(),
      ByteBuffer(bytes: [0x05, 0x01, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])
    )

    // server replies with an error
    let promise = self.channel.eventLoop.makePromise(of: Void.self)
    try! self.channel.pipeline.addHandler(ErrorHandler(promise: promise), position: .last)
      .wait()
    try self.channel.writeInbound(
      ByteBuffer(bytes: [0x05, 0x01, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])
    )
    //        XCTAssertThrowsError(try promise.futureResult.wait()) { e in
    //            XCTAssertEqual(e as? SOCKSError.ConnectionFailed, .init(reply: .serverFailure))
    //        }
  }

  func testWorkflowShouldStartAfterChannelActive() throws {
    XCTAssertFalse(channel.isActive)
    XCTAssertNil(try channel.readOutbound())

    try waitUntilConnected()
    XCTAssertTrue(channel.isActive)

    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [0x05, 0x01, 0x00]))
  }

  func testAddHandlerAfterChannelActived() throws {
    // reset the channel that was set up automatically
    XCTAssertNoThrow(try self.channel.close().wait())
    channel = nil
    channel = EmbeddedChannel()
    try waitUntilConnected()

    XCTAssertTrue(self.channel.isActive)

    XCTAssertNil(try channel.readOutbound())

    XCTAssertNoThrow(self.channel.pipeline.addHandler(handler))
    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [0x05, 0x01, 0x00]))
  }

  func testRemoveHandlerAfterHandshakeCompletedEventTriggered() throws {
    class EventHandler: ChannelInboundHandler {
      typealias InboundIn = NIOAny

      var establishedPromise: EventLoopPromise<Void>

      init(establishedPromise: EventLoopPromise<Void>) {
        self.establishedPromise = establishedPromise
      }

      func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        switch event {
        case is SOCKSUserEvent:
          self.establishedPromise.succeed(())
        default:
          break
        }
        context.fireUserInboundEventTriggered(event)
      }
    }

    let establishPromise = self.channel.eventLoop.makePromise(of: Void.self)
    let removalPromise = self.channel.eventLoop.makePromise(of: Void.self)
    establishPromise.futureResult.whenSuccess { _ in
      self.channel.pipeline.removeHandler(self.handler).cascade(to: removalPromise)
    }

    XCTAssertNoThrow(
      try self.channel.pipeline.addHandler(
        EventHandler(establishedPromise: establishPromise)
      ).wait()
    )

    try waitUntilConnected()

    // these writes should be buffered to be send out once the connection is established.
    self.channel.write(ByteBuffer(bytes: [1, 2, 3]), promise: nil)
    self.channel.flush()
    self.channel.write(ByteBuffer(bytes: [4, 5, 6]), promise: nil)

    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [0x05, 0x01, 0x00]))
    try self.channel.writeInbound(ByteBuffer(bytes: [0x05, 0x00]))
    XCTAssertEqual(
      try channel.readOutbound(),
      ByteBuffer(bytes: [0x05, 0x01, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])
    )
    try self.channel.writeInbound(
      ByteBuffer(bytes: [0x05, 0x00, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])
    )

    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [1, 2, 3]))

    XCTAssertNoThrow(try self.channel.writeAndFlush(ByteBuffer(bytes: [7, 8, 9])).wait())

    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [4, 5, 6]))
    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [7, 8, 9]))

    XCTAssertNoThrow(try removalPromise.futureResult.wait())
    XCTAssertThrowsError(
      try self.channel.pipeline.syncOperations.handler(type: SOCKS5ClientHandler.self)
    ) {
      XCTAssertEqual($0 as? ChannelPipelineError, .notFound)
    }
  }

  func testRemoveHandlerBeforeEstablished() throws {
    try waitUntilConnected()

    // these writes should be buffered to be send out once the connection is established.
    self.channel.write(ByteBuffer(bytes: [1, 2, 3]), promise: nil)
    self.channel.flush()
    self.channel.write(ByteBuffer(bytes: [4, 5, 6]), promise: nil)

    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [0x05, 0x01, 0x00]))
    try self.channel.writeInbound(ByteBuffer(bytes: [0x05, 0x00]))
    XCTAssertEqual(
      try channel.readOutbound(),
      ByteBuffer(bytes: [0x05, 0x01, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])
    )

    // we try to remove the handler before the connection is established.
    let removalPromise = self.channel.eventLoop.makePromise(of: Void.self)
    self.channel.pipeline.removeHandler(self.handler, promise: removalPromise)

    // establishes the connection
    try self.channel.writeInbound(
      ByteBuffer(bytes: [0x05, 0x00, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])
    )

    // write six more bytes - those should be passed through right away
    try self.channel.writeInbound(ByteBuffer(bytes: [1, 2, 3, 4, 5, 6]))
    XCTAssertEqual(try channel.readInbound(), ByteBuffer(bytes: [1, 2, 3, 4, 5, 6]))

    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [1, 2, 3]))

    XCTAssertNoThrow(try self.channel.writeAndFlush(ByteBuffer(bytes: [7, 8, 9])).wait())

    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [4, 5, 6]))
    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [7, 8, 9]))

    XCTAssertNoThrow(try removalPromise.futureResult.wait())
    XCTAssertThrowsError(
      try self.channel.pipeline.syncOperations.handler(type: SOCKS5ClientHandler.self)
    ) {
      XCTAssertEqual($0 as? ChannelPipelineError, .notFound)
    }
  }
}
