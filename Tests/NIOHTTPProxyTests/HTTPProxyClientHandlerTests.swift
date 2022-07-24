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

import NIO
import NIOHTTPProxy
import XCTest

class HTTPProxyClientHandlerTests: XCTestCase {

    var channel: EmbeddedChannel!
    var handler: HTTP1ClientCONNECTTunnelHandler!

    override func setUpWithError() throws {
        XCTAssertNil(self.channel)

        self.handler = .init(
            logger: .init(label: ""),
            username: "username",
            passwordReference: "passwordReference",
            authenticationRequired: false,
            preferHTTPTunneling: true,
            destinationAddress: .domainPort("swift.org", 443)
        )

        self.channel = EmbeddedChannel()
        try self.channel.pipeline.syncOperations.addHTTPClientHandlers()
        try self.channel.pipeline.syncOperations.addHandler(handler)
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
        XCTAssertNoThrow(try self.channel.close().wait())
        self.channel = EmbeddedChannel()
        XCTAssertNoThrow(try waitUtilConnected())
        XCTAssertTrue(self.channel.isActive)
        XCTAssertNil(try self.channel.readOutbound())
        XCTAssertNoThrow(try channel.pipeline.syncOperations.addHTTPClientHandlers())
        XCTAssertNoThrow(self.channel.pipeline.addHandler(self.handler))
        XCTAssertEqual(
            try channel.readOutbound(),
            ByteBuffer(string: "CONNECT swift.org:443 HTTP/1.1\r\n\r\n")
        )
        XCTAssertNoThrow(try channel.finish())
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

        handler = .init(
            logger: .init(label: ""),
            username: "username",
            passwordReference: "passwordReference",
            authenticationRequired: true,
            preferHTTPTunneling: true,
            destinationAddress: .domainPort("swift.org", 443)
        )

        channel = EmbeddedChannel()
        try channel.pipeline.syncOperations.addHTTPClientHandlers()
        try channel.pipeline.syncOperations.addHandler(handler)

        try waitUtilConnected()

        let writePromise = self.channel.eventLoop.makePromise(of: Void.self)
        channel.writeAndFlush(ByteBuffer(bytes: [1, 2, 3]), promise: writePromise)

        XCTAssertEqual(
            try channel.readOutbound(),
            ByteBuffer(
                string:
                    "CONNECT swift.org:443 HTTP/1.1\r\nproxy-authorization: Basic dXNlcm5hbWU6cGFzc3dvcmRSZWZlcmVuY2U=\r\n\r\n"
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

        handler = .init(
            logger: .init(label: ""),
            username: "username",
            passwordReference: "passwordReference",
            authenticationRequired: true,
            preferHTTPTunneling: true,
            destinationAddress: .domainPort("swift.org", 443)
        )

        channel = EmbeddedChannel()
        try channel.pipeline.syncOperations.addHTTPClientHandlers()
        try channel.pipeline.syncOperations.addHandler(handler)

        try waitUtilConnected()

        XCTAssertEqual(
            try channel.readOutbound(),
            ByteBuffer(
                string:
                    "CONNECT swift.org:443 HTTP/1.1\r\nproxy-authorization: Basic dXNlcm5hbWU6cGFzc3dvcmRSZWZlcmVuY2U=\r\n\r\n"
            )
        )
        try channel.writeInbound(
            ByteBuffer(string: "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
        )
        channel.embeddedEventLoop.advanceTime(to: .now())

        // TODO: Error handling
    }

    func testBasicAuthenticationRequired() throws {
        try waitUtilConnected()

        XCTAssertEqual(
            try channel.readOutbound(),
            ByteBuffer(string: "CONNECT swift.org:443 HTTP/1.1\r\n\r\n")
        )
        try channel.writeInbound(
            ByteBuffer(string: "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
        )
        channel.embeddedEventLoop.advanceTime(to: .now())

        // TODO: Error handling
    }

    func testBasicAuthenticationRequired0() throws {
        try waitUtilConnected()

        XCTAssertEqual(
            try channel.readOutbound(),
            ByteBuffer(string: "CONNECT swift.org:443 HTTP/1.1\r\n\r\n")
        )
        try channel.writeInbound(ByteBuffer(string: "\r\n"))
        try channel.writeInbound(
            ByteBuffer(string: "HTTP/1.1 407 Proxy Authentication Required\r\n")
        )
        try channel.writeInbound(ByteBuffer(string: "\r\n"))
        channel.embeddedEventLoop.advanceTime(to: .now())

        // TODO: Error handling
    }

    func testHTTPEncoderAndDecoderShouldBeenRemovedAfterEstablishedEventTriggered() throws {
        final class EventHandler: ChannelInboundHandler {
            typealias InboundIn = NIOAny

            let promise: EventLoopPromise<Void>

            init(promise: EventLoopPromise<Void>) {
                self.promise = promise
            }

            func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
                guard let e = event as? UserEvent else {
                    context.fireUserInboundEventTriggered(event)
                    return
                }

                switch e {
                    case .established:
                        promise.succeed(())
                }
            }
        }

        let promise = channel.eventLoop.makePromise(of: Void.self)
        XCTAssertNoThrow(try channel.pipeline.addHandler(EventHandler(promise: promise)).wait())
        try waitUtilConnected()

        try channel.writeInbound(ByteBuffer(string: "HTTP/1.1 200 OK\r\n\r\n"))
        channel.embeddedEventLoop.advanceTime(to: .now())

        XCTAssertNoThrow(try promise.futureResult.wait())

        XCTAssertThrowsError(
            try self.channel.pipeline.handler(type: HTTPRequestEncoder.self).wait()
        ) { error in
            XCTAssertEqual(error as? ChannelPipelineError, ChannelPipelineError.notFound)
        }

        XCTAssertThrowsError(
            try self.channel.pipeline.handler(type: ByteToMessageHandler<HTTPResponseDecoder>.self)
                .wait()
        ) { error in
            XCTAssertEqual(error as? ChannelPipelineError, ChannelPipelineError.notFound)
        }
    }
}
