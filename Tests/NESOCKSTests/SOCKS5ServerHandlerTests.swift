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

final class SOCKS5ServerHandlerTests: XCTestCase {

  var eventLoop: EmbeddedEventLoop!
  var channel: EmbeddedChannel!
  var handler: SOCKS5ServerHandler!
  var childChannel: EmbeddedChannel!

  override func setUpWithError() throws {
    XCTAssertNil(self.channel)
    XCTAssertNil(self.childChannel)

    eventLoop = EmbeddedEventLoop()

    self.childChannel = EmbeddedChannel(loop: eventLoop)

    let (localGlue, peerGlue) = GlueHandler.matchedPair()

    self.handler = SOCKS5ServerHandler(
      username: "",
      passwordReference: "",
      authenticationRequired: false
    ) { req in
      switch req.address {
      case .domainPort(let host, let port):
        let socketAddress = try! SocketAddress.makeAddressResolvingHost(
          host,
          port: port
        )
        return self.childChannel.connect(to: socketAddress).flatMap {
          self.channel.pipeline.addHandler(localGlue).flatMap {
            self.childChannel.pipeline.addHandler(peerGlue)
          }
        }
      case .socketAddress(let socketAddress):
        return self.childChannel.connect(to: socketAddress).flatMap {
          self.channel.pipeline.addHandler(localGlue).flatMap {
            self.childChannel.pipeline.addHandler(peerGlue)
          }
        }
      }
    }

    self.channel = EmbeddedChannel(handler: self.handler, loop: eventLoop)
    try self.channel.bind(to: .init(ipAddress: "127.0.0.1", port: 0)).wait()
  }

  override func tearDownWithError() throws {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    XCTAssertNotNil(self.channel)
    self.channel = nil
    self.childChannel = nil
  }

  func testWorkflow() throws {
    XCTAssertNil(try channel.readOutbound())
    XCTAssertFalse(childChannel.isActive)

    try channel.writeInbound(ByteBuffer(bytes: [0x05, 0x01, 0x00]))

    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [0x05, 0x00]))

    try channel.writeInbound(
      ByteBuffer(bytes: [0x05, 0x01, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])
    )
    XCTAssertTrue(childChannel.isActive)

    XCTAssertNotNil(try channel.readOutbound(as: ByteBuffer.self))

    try channel.writeOutbound(ByteBuffer(bytes: [1, 2, 3, 4, 5]))
    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [1, 2, 3, 4, 5]))

    try channel.writeInbound(ByteBuffer(bytes: [1, 2, 3, 4, 5]))
    XCTAssertNil(try channel.readOutbound())
    XCTAssertEqual(try childChannel.readOutbound(), ByteBuffer(bytes: [1, 2, 3, 4, 5]))

    try childChannel.writeInbound(ByteBuffer(bytes: [6, 7, 8]))
    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [6, 7, 8]))
  }

  func testWorkflowWithUsernamePasswordAuthentication() throws {
    let (localGlue, peerGlue) = GlueHandler.matchedPair()

    handler = SOCKS5ServerHandler(
      username: "username",
      passwordReference: "passwordReference",
      authenticationRequired: true
    ) { req in
      switch req.address {
      case .domainPort(let host, let port):
        let socketAddress = try! SocketAddress.makeAddressResolvingHost(
          host,
          port: port
        )
        return self.childChannel.connect(to: socketAddress).flatMap {
          self.channel.pipeline.addHandler(localGlue).flatMap {
            self.childChannel.pipeline.addHandler(peerGlue)
          }
        }
      case .socketAddress(let socketAddress):
        return self.childChannel.connect(to: socketAddress).flatMap {
          self.channel.pipeline.addHandler(localGlue).flatMap {
            self.childChannel.pipeline.addHandler(peerGlue)
          }
        }
      }
    }

    channel = EmbeddedChannel(handler: handler, loop: eventLoop)
    try channel.bind(to: .init(ipAddress: "127.0.0.1", port: 0)).wait()

    XCTAssertNil(try channel.readOutbound())
    XCTAssertFalse(childChannel.isActive)

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
    XCTAssertTrue(childChannel.isActive)

    // TODO: Assert response
    XCTAssertNotNil(try channel.readOutbound())

    try channel.writeInbound(ByteBuffer(bytes: [1, 2, 3, 4, 5]))
    XCTAssertNil(try channel.readOutbound())
    XCTAssertEqual(try childChannel.readOutbound(), ByteBuffer(bytes: [1, 2, 3, 4, 5]))

    try childChannel.writeInbound(ByteBuffer(bytes: [6, 7, 8]))
    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [6, 7, 8]))
  }

  func testWorkflowWithWrongUsernameOrPasswordAuthentication() throws {
    let (localGlue, peerGlue) = GlueHandler.matchedPair()

    handler = SOCKS5ServerHandler(
      username: "username",
      passwordReference: "passwordReference",
      authenticationRequired: true
    ) { req in
      switch req.address {
      case .domainPort(let host, let port):
        let socketAddress = try! SocketAddress.makeAddressResolvingHost(
          host,
          port: port
        )
        return self.childChannel.connect(to: socketAddress).flatMap {
          self.channel.pipeline.addHandler(localGlue).flatMap {
            self.childChannel.pipeline.addHandler(peerGlue)
          }
        }
      case .socketAddress(let socketAddress):
        return self.childChannel.connect(to: socketAddress).flatMap {
          self.channel.pipeline.addHandler(localGlue).flatMap {
            self.childChannel.pipeline.addHandler(peerGlue)
          }
        }
      }
    }

    channel = EmbeddedChannel(handler: handler, loop: eventLoop)
    try channel.bind(to: .init(ipAddress: "127.0.0.1", port: 0)).wait()

    XCTAssertNil(try channel.readOutbound())
    XCTAssertFalse(childChannel.isActive)

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
    // TODO: Assert response
    XCTAssertNotNil(try channel.readOutbound())

    // any inbound data should now go straight through
    try channel.writeInbound(ByteBuffer(bytes: [1, 2, 3, 4, 5]))
    XCTAssertNil(try channel.readOutbound())
    XCTAssertEqual(try childChannel.readOutbound(), ByteBuffer(bytes: [1, 2, 3, 4, 5]))

    try childChannel.writeInbound(ByteBuffer(bytes: [6, 7, 8]))
    XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [6, 7, 8]))
  }
}
