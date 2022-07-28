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

import NIOCore
import NIOEmbedded
import NIOSOCKS5
import XCTest

final class SOCKS5ServerHandlerTests: XCTestCase {

    var channel: EmbeddedChannel!
    var handler: SOCKS5ServerHandler!
    var childChannel: EmbeddedChannel!

    override func setUpWithError() throws {
        XCTAssertNil(self.channel)
        XCTAssertNil(self.childChannel)

        let eventLoop = EmbeddedEventLoop()

        self.childChannel = EmbeddedChannel()

        self.handler = SOCKS5ServerHandler(
            username: "",
            passwordReference: "",
            authenticationRequired: false
        ) { address in
            switch address {
                case .domainPort(let host, let port):
                    let socketAddress = try! SocketAddress.makeAddressResolvingHost(
                        host,
                        port: port
                    )
                    return self.childChannel.connect(to: socketAddress).map {
                        self.childChannel
                    }
                case .socketAddress(let socketAddress):
                    return self.childChannel.connect(to: socketAddress).map {
                        self.childChannel
                    }
            }
        }

        self.channel = EmbeddedChannel(handler: self.handler, loop: eventLoop)
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

        XCTAssertEqual(
            try channel.readOutbound(),
            ByteBuffer(bytes: [0x05, 0x00, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])
        )

        try channel.writeOutbound(ByteBuffer(bytes: [1, 2, 3, 4, 5]))
        XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [1, 2, 3, 4, 5]))

        try channel.writeInbound(ByteBuffer(bytes: [1, 2, 3, 4, 5]))
        XCTAssertNil(try channel.readOutbound())
        XCTAssertEqual(try childChannel.readOutbound(), ByteBuffer(bytes: [1, 2, 3, 4, 5]))

        try childChannel.writeInbound(ByteBuffer(bytes: [6, 7, 8]))
        XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [6, 7, 8]))
    }

    func testWorkflowWithUsernamePasswordAuthentication() throws {
        let eventLoop = EmbeddedEventLoop()

        let childChannel = EmbeddedChannel()

        let handler = SOCKS5ServerHandler(
            username: "username",
            passwordReference: "passwordReference",
            authenticationRequired: true
        ) { address in
            switch address {
                case .domainPort(let host, let port):
                    let socketAddress = try! SocketAddress.makeAddressResolvingHost(
                        host,
                        port: port
                    )
                    return childChannel.connect(to: socketAddress).map {
                        childChannel
                    }
                case .socketAddress(let socketAddress):
                    return childChannel.connect(to: socketAddress).map {
                        childChannel
                    }
            }
        }

        let channel = EmbeddedChannel(handler: handler, loop: eventLoop)

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

        XCTAssertEqual(
            try channel.readOutbound(),
            ByteBuffer(bytes: [0x05, 0x00, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])
        )

        try channel.writeInbound(ByteBuffer(bytes: [1, 2, 3, 4, 5]))
        XCTAssertNil(try channel.readOutbound())
        XCTAssertEqual(try childChannel.readOutbound(), ByteBuffer(bytes: [1, 2, 3, 4, 5]))

        try childChannel.writeInbound(ByteBuffer(bytes: [6, 7, 8]))
        XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [6, 7, 8]))
    }

    func testWorkflowWithWrongUsernameOrPasswordAuthentication() throws {
        let eventLoop = EmbeddedEventLoop()

        let childChannel = EmbeddedChannel()

        let handler = SOCKS5ServerHandler(
            username: "username",
            passwordReference: "passwordReference",
            authenticationRequired: true
        ) { address in
            switch address {
                case .domainPort(let host, let port):
                    let socketAddress = try! SocketAddress.makeAddressResolvingHost(
                        host,
                        port: port
                    )
                    return childChannel.connect(to: socketAddress).map {
                        childChannel
                    }
                case .socketAddress(let socketAddress):
                    return childChannel.connect(to: socketAddress).map {
                        childChannel
                    }
            }
        }

        let channel = EmbeddedChannel(handler: handler, loop: eventLoop)

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
        XCTAssertEqual(channel.isActive, false)
        XCTAssertThrowsError(try channel.finish()) { error in
            XCTAssertEqual(error as? ChannelError, ChannelError.alreadyClosed)
        }
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
        XCTAssertEqual(
            try channel.readOutbound(),
            ByteBuffer(bytes: [0x05, 0x00, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])
        )

        // any inbound data should now go straight through
        try channel.writeInbound(ByteBuffer(bytes: [1, 2, 3, 4, 5]))
        XCTAssertNil(try channel.readOutbound())
        XCTAssertEqual(try childChannel.readOutbound(), ByteBuffer(bytes: [1, 2, 3, 4, 5]))

        try childChannel.writeInbound(ByteBuffer(bytes: [6, 7, 8]))
        XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [6, 7, 8]))
    }

    func testBuffering() throws {
        let writePromise = channel.eventLoop.makePromise(of: Void.self)
        channel.writeAndFlush(ByteBuffer(bytes: [1, 2, 3, 4, 5]), promise: writePromise)
        XCTAssertNil(try channel.readOutbound())
        try channel.writeInbound(ByteBuffer(bytes: [0x05, 0x01, 0x00]))
        XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [0x05, 0x00]))
        try channel.writeInbound(
            ByteBuffer(bytes: [0x05, 0x01, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])
        )
        XCTAssertEqual(
            try channel.readOutbound(),
            ByteBuffer(bytes: [0x05, 0x00, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])
        )

        XCTAssertNoThrow(try writePromise.futureResult.wait())
        XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [1, 2, 3, 4, 5]))
    }

    func testBufferingWithMark() throws {
        let writePromise1 = channel.eventLoop.makePromise(of: Void.self)
        let writePromise2 = channel.eventLoop.makePromise(of: Void.self)
        channel.write(ByteBuffer(bytes: [1, 2, 3]), promise: writePromise1)
        channel.flush()
        channel.write(ByteBuffer(bytes: [4, 5, 6]), promise: writePromise2)

        XCTAssertNil(try channel.readOutbound())
        try channel.writeInbound(ByteBuffer(bytes: [0x05, 0x01, 0x00]))
        XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [0x05, 0x00]))
        try channel.writeInbound(
            ByteBuffer(bytes: [0x05, 0x01, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])
        )
        XCTAssertEqual(
            try channel.readOutbound(),
            ByteBuffer(bytes: [0x05, 0x00, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])
        )

        XCTAssertNoThrow(try writePromise1.futureResult.wait())
        XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [1, 2, 3]))

        XCTAssertNoThrow(try channel.writeAndFlush(ByteBuffer(bytes: [7, 8, 9])).wait())
        XCTAssertNoThrow(try writePromise2.futureResult.wait())
        XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [4, 5, 6]))
        XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [7, 8, 9]))
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

        let establishPromise = channel.eventLoop.makePromise(of: Void.self)
        let removalPromise = channel.eventLoop.makePromise(of: Void.self)
        establishPromise.futureResult.whenSuccess { _ in
            self.channel.pipeline.removeHandler(self.handler).cascade(to: removalPromise)
        }

        XCTAssertNoThrow(
            try channel.pipeline.addHandler(
                EventHandler(establishedPromise: establishPromise)
            ).wait()
        )

        // these writes should be buffered to be send out once the connection is established.
        self.channel.write(ByteBuffer(bytes: [1, 2, 3]), promise: nil)
        self.channel.flush()
        self.channel.write(ByteBuffer(bytes: [4, 5, 6]), promise: nil)

        try channel.writeInbound(ByteBuffer(bytes: [0x05, 0x01, 0x00]))
        XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [0x05, 0x00]))
        try channel.writeInbound(
            ByteBuffer(bytes: [0x05, 0x01, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])
        )
        XCTAssertEqual(
            try channel.readOutbound(),
            ByteBuffer(bytes: [0x05, 0x00, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])
        )

        XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [1, 2, 3]))

        XCTAssertNoThrow(try self.channel.writeAndFlush(ByteBuffer(bytes: [7, 8, 9])).wait())

        XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [4, 5, 6]))
        XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [7, 8, 9]))

        XCTAssertNoThrow(try removalPromise.futureResult.wait())
        XCTAssertThrowsError(
            try self.channel.pipeline.syncOperations.handler(type: SOCKS5ServerHandler.self)
        ) {
            XCTAssertEqual($0 as? ChannelPipelineError, .notFound)
        }
    }

    func testRemoveHandlerBeforeEstablished() throws {

        // these writes should be buffered to be send out once the connection is established.
        channel.write(ByteBuffer(bytes: [1, 2, 3]), promise: nil)
        channel.flush()
        channel.write(ByteBuffer(bytes: [4, 5, 6]), promise: nil)

        try channel.writeInbound(ByteBuffer(bytes: [0x05, 0x01, 0x00]))
        XCTAssertEqual(try channel.readOutbound(), ByteBuffer(bytes: [0x05, 0x00]))

        // we try to remove the handler before the connection is established.
        let removalPromise = channel.eventLoop.makePromise(of: Void.self)
        channel.pipeline.removeHandler(handler, promise: removalPromise)

        // establishes the connection
        try channel.writeInbound(
            ByteBuffer(bytes: [0x05, 0x01, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])
        )
        XCTAssertEqual(
            try channel.readOutbound(),
            ByteBuffer(bytes: [0x05, 0x00, 0x00, 0x01, 192, 168, 1, 1, 0x00, 0x50])
        )

        // write six more bytes - those should be passed through right away
        try self.channel.writeInbound(ByteBuffer(bytes: [1, 2, 3, 4, 5, 6]))
        XCTAssertEqual(try childChannel.readOutbound(), ByteBuffer(bytes: [1, 2, 3, 4, 5, 6]))

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
