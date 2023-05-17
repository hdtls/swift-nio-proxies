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
import NIOWebSocket
import XCTest

@testable import NECore

final class WebSocketFrameProducerTests: XCTestCase {

  var handler: WebSocketFrameProducer!
  var channel: EmbeddedChannel!

  override func setUpWithError() throws {
    XCTAssertNil(channel)
    handler = WebSocketFrameProducer()
    channel = EmbeddedChannel(handler: handler)
    try channel.connect(to: .init(ipAddress: "127.0.0.1", port: 0)).wait()
  }

  override func tearDown() {
    XCTAssertNotNil(channel)
    XCTAssertNoThrow(XCTAssertTrue(try channel.finish().isClean))
    channel = nil
  }

  func testWriteFileRegion() throws {
    let fh = try NIOFileHandle(path: #file)
    let fr = try FileRegion(fileHandle: fh)
    try fh.close()
    XCTAssertThrowsError(try channel.writeOutbound(fr))
  }

  func testWriteByteBuffer() throws {
    let byteBuffer = ByteBuffer(bytes: [0x00, 0x01])
    XCTAssertNoThrow(try channel.writeOutbound(byteBuffer))
    let frame = try channel.readOutbound(as: WebSocketFrame.self)

    XCTAssertEqual(frame?.opcode, .binary)
    XCTAssertEqual(frame?.data, byteBuffer)
  }

  func testReceiveTextAndBinary() throws {
    let textFrameData = ByteBuffer(string: "Hello world!")
    XCTAssertNoThrow(try channel.writeInbound(WebSocketFrame(opcode: .text, data: textFrameData)))
    XCTAssertNoThrow(XCTAssertEqual(try channel.readInbound(), textFrameData))

    let binaryFrameData = ByteBuffer(bytes: [0x00, 0x01])
    XCTAssertNoThrow(
      try channel.writeInbound(WebSocketFrame(opcode: .binary, data: binaryFrameData))
    )
    XCTAssertNoThrow(XCTAssertEqual(try channel.readInbound(), binaryFrameData))
  }

  func testIgnoreWhenReceiveContinuationFrame() {
    let binaryFrameData = ByteBuffer(bytes: [0x00, 0x01])
    XCTAssertNoThrow(
      try channel.writeInbound(WebSocketFrame(opcode: .continuation, data: binaryFrameData))
    )
    XCTAssertNoThrow(XCTAssertNil(try channel.readInbound()))
  }

  func testCloseChannelWhenReceiveConnectionCloseFrame() throws {
    let channel = EmbeddedChannel(handler: WebSocketFrameProducer())
    try channel.connect(to: .init(ipAddress: "0.0.0.0", port: 0)).wait()

    var data = ByteBuffer()
    data.write(webSocketErrorCode: .messageTooLarge)
    let frame = WebSocketFrame(fin: true, opcode: .connectionClose, data: data)
    XCTAssertNoThrow(try channel.writeInbound(frame))

    XCTAssertNoThrow(XCTAssertTrue(try channel.finish(acceptAlreadyClosed: true).hasLeftOvers))

    XCTAssertEqual(try channel.readOutbound(as: WebSocketFrame.self)?.data, data)
    XCTAssertFalse(try channel.finish(acceptAlreadyClosed: true).hasLeftOvers)
  }

  func testReceivePingFrame() throws {
    let data = ByteBuffer(string: "boom!!")
    var frame = WebSocketFrame(fin: true, opcode: .ping, data: data)
    XCTAssertNoThrow(try channel.writeInbound(frame))

    frame = try channel.readOutbound(as: WebSocketFrame.self)!
    XCTAssertEqual(frame.opcode, .pong)
    XCTAssertEqual(frame.data, data)
  }

  func testReceiveUnFinPingFrame() throws {
    var frame = WebSocketFrame(opcode: .ping, data: ByteBuffer())
    XCTAssertNoThrow(try channel.writeInbound(frame))
    frame = try channel.readOutbound(as: WebSocketFrame.self)!
    XCTAssertEqual(frame.opcode, .connectionClose)
  }

  func testReceivePongFrame() throws {
    let frame = WebSocketFrame(fin: true, opcode: .pong, data: ByteBuffer())
    XCTAssertNoThrow(try channel.writeInbound(frame))
  }

  func testReceiveUnFinPongFrame() throws {
    var frame = WebSocketFrame(opcode: .pong, data: ByteBuffer())
    XCTAssertNoThrow(try channel.writeInbound(frame))
    frame = try channel.readOutbound(as: WebSocketFrame.self)!
    XCTAssertEqual(frame.opcode, .connectionClose)
  }

  func testReceiveConnectionCloseAfterReceiveUnFinPingFrame() throws {
    let channel = EmbeddedChannel(handler: WebSocketFrameProducer())
    try channel.connect(to: .init(ipAddress: "0.0.0.0", port: 0)).wait()

    var frame = WebSocketFrame(opcode: .ping, data: ByteBuffer())
    XCTAssertNoThrow(try channel.writeInbound(frame))

    frame = WebSocketFrame(fin: true, opcode: .connectionClose, data: ByteBuffer())
    XCTAssertNoThrow(try channel.writeInbound(frame))
    XCTAssertThrowsError(try channel.finish()) {
      XCTAssertEqual($0 as? ChannelError, .alreadyClosed)
    }
  }

  func testReceiveConnectionCloseAfterReceiveUnFinPongFrame() throws {
    let channel = EmbeddedChannel(handler: WebSocketFrameProducer())
    try channel.connect(to: .init(ipAddress: "0.0.0.0", port: 0)).wait()

    var frame = WebSocketFrame(opcode: .pong, data: ByteBuffer())
    XCTAssertNoThrow(try channel.writeInbound(frame))

    frame = WebSocketFrame(fin: true, opcode: .connectionClose, data: ByteBuffer())
    XCTAssertNoThrow(try channel.writeInbound(frame))
    XCTAssertThrowsError(try channel.finish()) {
      XCTAssertEqual($0 as? ChannelError, .alreadyClosed)
    }
  }
}
