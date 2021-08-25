//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright © 2019 Netbot Ltd. and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import XCTest
@testable import Netbot

extension ByteBuffer {
    static func writeString(_ str: String) -> ByteBuffer {
        var buffer = ByteBufferAllocator().buffer(capacity: str.utf8.count)
        buffer.writeString(str)
        return buffer
    }
}

final class NIOVPNProtoShadowsocksTests: XCTestCase {

    func testSSClientHandlerRead() throws {
        let channel = EmbeddedChannel()

        let handler = try SSClientProxyHandler(configuration: .init(password: "Netbot", algorithm: 0))

        try channel.pipeline.addHandler(handler).wait()

        try write(channel: channel, string: "This is ss proxy handler test HEAD.")

        try write(channel: channel, string: "This is ss proxy handler test BODY.")

        try write(channel: channel, string: "This is ss proxy handler test END.")

        XCTAssertTrue(try channel.finish().isClean)
    }

    func write(channel: EmbeddedChannel, string: String) throws {

        // Send a write, which is buffered.
        try channel.writeOutbound(ByteBuffer.writeString(string))

        var writeBuffer: ByteBuffer = try channel.readOutbound()!

        var readBuffer = ByteBufferAllocator().buffer(capacity: writeBuffer.readableBytes)
        readBuffer.writeBytes(writeBuffer.readBytes(length: writeBuffer.readableBytes)!)
        try channel.writeInbound(readBuffer)

        var byteBuffer = try channel.readInbound(as: ByteBuffer.self)!

        XCTAssertNoThrow(XCTAssertEqual(byteBuffer.readBytes(length: byteBuffer.readableBytes), Array(string.utf8)))
    }
}
