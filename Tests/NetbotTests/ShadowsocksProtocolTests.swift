//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2021 Junfeng Zhang. and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import XCTest
@testable import Netbot
@testable import Shadowsocks

final class ShadowsocksCodecTests: XCTestCase {

    private var channel: EmbeddedChannel!
    private var eventLoop: EmbeddedEventLoop {
        return channel.embeddedEventLoop
    }
    
    override func setUp() {
        channel = EmbeddedChannel()
    }
    
    override func tearDown() {
        XCTAssertNoThrow(try channel?.finish(acceptAlreadyClosed: true))
        channel = nil
    }
    
    func testEncryptDecrypt() {
        
    }
    
    func testCodec() throws {
        let shadowsocksEncoder = RequestEncoder(taskAddress: .socketAddress(try .init(ipAddress: "127.0.0.1", port: 0)), secretKey: "password")
        let shadowsocksDecoder = RequestDecoder(secretKey: "password")
        
        XCTAssertNoThrow(try channel.pipeline.addHandler(MessageToByteHandler(shadowsocksEncoder)).wait())
        let peer = EmbeddedChannel()
        XCTAssertNoThrow(try peer.pipeline.addHandler(ByteToMessageHandler(shadowsocksDecoder)).wait())

        let expected = Array<String>(repeating: "", count: 1).map { _ in
            UUID().uuidString
        }

        for (index, uuidString) in expected.enumerated() {
            try channel.writeOutbound(ByteBuffer(string: uuidString))
            let out: ByteBuffer = try channel.readOutbound()!
            XCTAssertNotNil(out)
            
            try peer.writeInbound(out)
            
            var part = try peer.readInbound(as: Packet.self)
//            if index == 0 {
//                part = try peer.readInbound(as: SSServerRequestPart.self)
//            }
//
//            XCTAssertNotNil(part)
//
//            switch part {
//                case .buffer(var byteBuffer):
//                    XCTAssertEqual(uuidString, byteBuffer.readString(length: byteBuffer.readableBytes)!)
//                default:
//                    XCTFail()
//            }
        }
    }

}
