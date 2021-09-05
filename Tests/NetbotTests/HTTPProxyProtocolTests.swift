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

fileprivate func setupHTTPProxyClient(
    group: EventLoopGroup,
    credential: HTTP.Credential? = nil,
    targetAddress: SocketAddress,
    established: EventLoopPromise<Void>? = nil
) -> EventLoopFuture<Channel> {
    ServerBootstrap(group: group)
        .serverChannelOption(ChannelOptions.backlog, value: Int32(1024))
        .serverChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: SocketOptionValue(1))
        .childChannelInitializer { channel in
            channel.pipeline.addHandlers([
                HTTPResponseEncoder(),
                ByteToMessageHandler(HTTPRequestDecoder(leftOverBytesStrategy: .forwardBytes)),
                HTTP1ClientCONNECTTunnelHandler(credential: credential, targetAddress: targetAddress, established: established)
            ])
        }
        .childChannelOption(ChannelOptions.socket(IPPROTO_TCP, TCP_NODELAY), value: SocketOptionValue(1))
        .childChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: SocketOptionValue(1))
        .childChannelOption(ChannelOptions.maxMessagesPerRead, value: 1)
        .bind(host: "127.0.0.1", port: 0)
}

class EventRecord<T>: ChannelInboundHandler {
    typealias InboundIn = Any
    
    var events: [T] = []
    
    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        events.append(event as! T)
        context.fireUserInboundEventTriggered(event)
    }
}

func assert(_ response: String, expectedLine: String, expectedHTTPHeaders: [String]) {
    var lines = response.split(separator: "\r\n", omittingEmptySubsequences: false).map(String.init)
    
        // We never expect a response end here. This means we need the last two entries to be empty strings.
    XCTAssertEqual("", lines.removeLast())
    XCTAssertEqual("", lines.removeLast())
    XCTAssertEqual("0", lines.removeLast())
    XCTAssertEqual("", lines.removeLast())
    XCTAssertEqual("transfer-encoding: chunked", lines.removeLast().lowercased())
    
        // Check the response line is correct.
    let actualResponseLine = lines.removeFirst()
    XCTAssertEqual(expectedLine, actualResponseLine)
    
    lines = lines.map({ $0.lowercased() })
    
        // For each header, find it in the actual response headers and remove it.
    for expectedHeader in expectedHTTPHeaders {
        guard let index = lines.firstIndex(of: expectedHeader.lowercased()) else {
            XCTFail("Could not find header \"\(expectedHeader)\"")
            return
        }
        lines.remove(at: index)
    }
    
        // That should be all the headers.
    XCTAssertEqual(lines.count, 0)
}

final class HTTPProxyProtocolTests: XCTestCase {
    
    var channel: EmbeddedChannel!
    var handler: HTTP1ClientCONNECTTunnelHandler!
    
    override func setUpWithError() throws {
        XCTAssertNil(channel)
        handler = .init(targetAddress: try .init(ipAddress: "127.0.0.1", port: 6152))
        channel = EmbeddedChannel(handler: handler)
    }
    
    func connect() {
        try! self.channel.connect(to: .init(ipAddress: "127.0.0.1", port: 80)).wait()
    }
    
    func testClientHandlerWithoutServerResponse() throws {
        connect()
        
        XCTAssertEqual(try channel.readOutbound(as: HTTPClientRequestPart.self), .head(.init(version: .http1_1, method: .CONNECT, uri: "127.0.0.1:6152", headers: .init())))
        XCTAssertNil(try channel.readInbound())
        XCTAssertEqual(try channel.readOutbound(as: HTTPClientRequestPart.self), .end(nil))
        XCTAssertNil(try channel.readInbound())
        channel.write(ByteBuffer(string: "hello"), promise: nil)
        XCTAssertNil(try channel.readOutbound())
        XCTAssertNil(try channel.readInbound())
    }

    func testReceiveHTTPEndPartBeforeHeadReceived() {
        connect()
        XCTAssertThrowsError(try channel.writeInbound(HTTPClientResponsePart.end(nil)))
        XCTAssertNoThrow(try channel.finish(acceptAlreadyClosed: true))
    }
}
import Crypto
