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
@testable import NIO
@testable import NIOHTTP1
@testable import NWHTTPProxy

class ArrayAccumulationHandler<T>: ChannelInboundHandler {
    typealias InboundIn = T
    private var receiveds: [T] = []
    private var allDoneBlock: DispatchWorkItem! = nil

    public init(completion: @escaping ([T]) -> Void) {
        self.allDoneBlock = DispatchWorkItem { [unowned self] () -> Void in
            completion(self.receiveds)
        }
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        self.receiveds.append(self.unwrapInboundIn(data))
    }

    public func channelUnregistered(context: ChannelHandlerContext) {
        self.allDoneBlock.perform()
    }

    public func syncWaitForCompletion() {
        self.allDoneBlock.wait()
    }
}

extension ChannelPipeline {
    func assertDoesNotContainUpgrader() throws {
        try self.assertDoesNotContain(handlerType: HTTPProxyUpgradeHandler.self)
    }

    func assertDoesNotContain<Handler: ChannelHandler>(handlerType: Handler.Type,
                                                       file: StaticString = #file,
                                                       line: UInt = #line) throws {
        do {
            let context = try self.context(handlerType: handlerType).wait()
            XCTFail("Found handler: \(context.handler)", file: file, line: line)
        } catch ChannelPipelineError.notFound {
            // Nothing to see here
        }
    }

    func assertContainsUpgrader() throws {
        try self.assertContains(handlerType: HTTPProxyUpgradeHandler.self)
    }

    func assertContains<Handler: ChannelHandler>(handlerType: Handler.Type) throws {
        do {
            _ = try self.context(handlerType: handlerType).wait()
        } catch ChannelPipelineError.notFound {
            XCTFail("Did not find handler")
        }
    }

    // Waits up to 1 second for the upgrader to be removed by polling the pipeline
    // every 50ms checking for the handler.
    func waitForUpgraderToBeRemoved() throws {
        for _ in 0..<20 {
            do {
                _ = try self.context(handlerType: HTTPProxyUpgradeHandler.self).wait()
                // handler present, keep waiting
                usleep(50)
            } catch ChannelPipelineError.notFound {
                // No upgrader, we're good.
                return
            }
        }

        XCTFail("Upgrader never removed")
    }
}

private enum Explosion: Error {
    case KABOOM
}

private func serverHTTPChannelWithAutoremoval(
    group: EventLoopGroup,
    pipelining: Bool,
    upgrader: HTTPProxyUpgrader,
    extraHandlers: [ChannelHandler],
    completion: @escaping (ChannelHandlerContext) -> Void
    ) throws -> (Channel, EventLoopFuture<Channel>) {

    let p = group.next().makePromise(of: Channel.self)
    let c = try ServerBootstrap(group: group)
        .serverChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: 1)
        .childChannelInitializer { channel in
            p.succeed(channel)

            return channel.pipeline.configureHTTPProxyPipeline(
                withPipeliningAssistance: pipelining,
                httpProxyUpgrader: upgrader,
                completion: completion
                ).flatMap {
                    let futureResults = extraHandlers.map { channel.pipeline.addHandler($0) }
                    return EventLoopFuture.andAllSucceed(futureResults, on: channel.eventLoop)
            }
        }.bind(host: "127.0.0.1", port: 0).wait()
    return (c, p.futureResult)
}

private func connectedClientChannel(group: EventLoopGroup, serverAddress: SocketAddress) throws -> Channel {
    return try ClientBootstrap(group: group)
        .connect(to: serverAddress)
        .wait()
}

typealias HTTPAdapter = (eventLoopGroup: EventLoopGroup, server: Channel, client: Channel, extra: Channel)

private func setUpTestWithAutoremoval(
    pipelining: Bool = false,
    upgrader: HTTPProxyUpgrader,
    extraHandlers: [ChannelHandler],
    completion: @escaping (ChannelHandlerContext) -> Void
    ) throws -> (EventLoopGroup, Channel, Channel, Channel) {
    let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
    let (serverChannel, future) = try serverHTTPChannelWithAutoremoval(group: group,
                                                                       pipelining: pipelining,
                                                                       upgrader: upgrader,
                                                                       extraHandlers: extraHandlers,
                                                                       completion: completion)
    let clientChannel = try connectedClientChannel(group: group, serverAddress: serverChannel.localAddress!)
    return (group, serverChannel, clientChannel, try future.wait())
}

private func setupHTTPProxy(pipelining: Bool = false,
                   builder: @escaping HTTPProxyUpgrader.ProxyHeadersEventLoop,
                   upgrade: @escaping HTTPProxyUpgrader.ProxyUpgradeEventLoop,
                   extraHTTPHandlers: [ChannelHandler] = [],
                   extraProxyHandlers: [RemovableChannelHandler] = [],
                   completion: @escaping (ChannelHandlerContext) -> Void) throws -> HTTPAdapter {

    let upgrader = HTTPProxyUpgrader.init(proxyHeadersEventLoop: builder, proxyUpgradeEventLoop: upgrade)

    return try setUpTestWithAutoremoval(pipelining: pipelining,
                                    upgrader: upgrader,
                                    extraHandlers: extraHTTPHandlers,
                                    completion: completion)
}

extension ByteBuffer {
    static func writeString(_ str: String) -> ByteBuffer {
        var buffer = ByteBufferAllocator().buffer(capacity: str.utf8.count)
        buffer.writeString(str)
        return buffer
    }
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

final class NIOVPNProtoHTTPTests: XCTestCase {

    func testUpgradeWithoutSendHttpEndPart() throws {
        let channel = EmbeddedChannel()
        defer {
            XCTAssertEqual(true, try? channel.finish().isClean)
        }

        let upgrader = HTTPProxyUpgrader.init(proxyHeadersEventLoop: { (c, head, headers) -> EventLoopFuture<HTTPHeaders> in
            XCTFail()
            return c.eventLoop.makeFailedFuture(Explosion.KABOOM)
        }) { (context, head) -> EventLoopFuture<Void> in
            XCTFail()
            return context.channel.eventLoop.makeSucceededFuture(())
        }

        let handler = HTTPProxyUpgradeHandler.init(httpEncoder: HTTPResponseEncoder(),
                                                   extraHTTPHandlers: [],
                                                   upgrader: upgrader) { (_) in
                                                    XCTFail("Upgrade completed")
        }

        let head = HTTPRequestHead.init(version: .init(major: 1, minor: 1),
                                        method: .CONNECT,
                                        uri: "*",
                                        headers: HTTPHeaders())
        XCTAssertNoThrow(try channel.pipeline.addHandler(handler).wait())
        XCTAssertNoThrow(try channel.writeInbound(HTTPServerRequestPart.head(head)))

        // The handler removed itself from the pipeline and passed the unexpected
        // data on.
        try channel.pipeline.assertContainsUpgrader()
    }

    func testUpgradeHandlerBufferOnUnexpectedOrdering() throws {
        let channel = EmbeddedChannel()
        defer {
            XCTAssertEqual(true, try? channel.finish().isClean)
        }

        let upgrader = HTTPProxyUpgrader.init(proxyHeadersEventLoop: { (c, head, headers) -> EventLoopFuture<HTTPHeaders> in
            XCTFail()
            return c.eventLoop.makeFailedFuture(Explosion.KABOOM)
        }) { (context, head) -> EventLoopFuture<Void> in
            XCTFail()
            return context.channel.eventLoop.makeSucceededFuture(())
        }

        let handler = HTTPProxyUpgradeHandler.init(httpEncoder: HTTPResponseEncoder(),
                                                   extraHTTPHandlers: [],
                                                   upgrader: upgrader) { (_) in
                                                    XCTFail("Upgrade completed")
        }

        let data = HTTPServerRequestPart.body(ByteBuffer.writeString("hello"))

        XCTAssertNoThrow(try channel.pipeline.addHandler(handler).wait())
        XCTAssertThrowsError(try channel.writeInbound(data))

        // The handler removed itself from the pipeline and passed the unexpected
        // data on.
        try channel.pipeline.assertContainsUpgrader()
    }

    func testUpgradeWhenBuildProxyResponseFailed() throws {
        let channel = EmbeddedChannel()
        defer {
            XCTAssertEqual(true, try? channel.finish().isClean)
        }

        let upgrader = HTTPProxyUpgrader.init(proxyHeadersEventLoop: { (c, head, headers) -> EventLoopFuture<HTTPHeaders> in
            return c.eventLoop.makeFailedFuture(Explosion.KABOOM)
        }) { (context, head) -> EventLoopFuture<Void> in
            XCTFail()
            return context.channel.eventLoop.makeSucceededFuture(())
        }

        let handler = HTTPProxyUpgradeHandler.init(httpEncoder: HTTPResponseEncoder(),
                                                   extraHTTPHandlers: [],
                                                   upgrader: upgrader) { (_) in
                                                    XCTFail("Upgrade completed")
        }

        let head = HTTPRequestHead.init(version: .init(major: 1, minor: 1),
                                        method: .CONNECT,
                                        uri: "*",
                                        headers: HTTPHeaders())
        XCTAssertNoThrow(try channel.pipeline.addHandler(handler).wait())
        XCTAssertNoThrow(try channel.writeInbound(HTTPServerRequestPart.head(head)))
        XCTAssertThrowsError(try channel.writeInbound(HTTPServerRequestPart.end(nil)))

        // The handler removed itself from the pipeline and passed the unexpected
        // data on.
        try channel.pipeline.assertContainsUpgrader()
    }

    func testSimpleSucceedUpgradeHandler() throws {
        var head: HTTPRequestHead?
        var upgradeFired: Bool = false
        var upgradeIsCompleted: Bool = false

        let setup = try setupHTTPProxy(builder: { (c, head, headers) -> EventLoopFuture<HTTPHeaders> in
            c.eventLoop.makeSucceededFuture(headers)
        }, upgrade: { (c, h) -> EventLoopFuture<Void> in
            head = h
            XCTAssert(upgradeIsCompleted)
            upgradeFired = true
            return c.channel.eventLoop.makeSucceededFuture(())
        }) { (c) in
            XCTAssertNil(head)
            upgradeIsCompleted = true
            c.close(promise: nil)
        }

        defer {
            XCTAssertNoThrow(try setup.eventLoopGroup.syncShutdownGracefully())
        }

        let completePromise = setup.eventLoopGroup.next().makePromise(of: Void.self)
        let clientHandler = ArrayAccumulationHandler<ByteBuffer> { buffers in
            let resultString = buffers.map { $0.getString(at: $0.readerIndex, length: $0.readableBytes)! }.joined(separator: "")
            assert(resultString,
                           expectedLine: "HTTP/1.1 200 OK",
                           expectedHTTPHeaders: ["connection: established"])
            completePromise.succeed(())
        }
        XCTAssertNoThrow(try setup.client.pipeline.addHandler(clientHandler).wait())

        let request = "CONNECT * HTTP/1.1\r\nHost: localhost\r\n\r\n"
        XCTAssertNoThrow(try setup.client.writeAndFlush(NIOAny(ByteBuffer.writeString(request))).wait())

        XCTAssertNoThrow(try completePromise.futureResult.wait())

        XCTAssert(upgradeFired)
        XCTAssert(upgradeIsCompleted)

        try setup.extra.pipeline.assertDoesNotContainUpgrader()
    }

    func testUpgradeFiresUserEvent() throws {
        // The user event is fired last, so we don't see it until both other callbacks
        // have fired.
        let record = EventRecord<HTTPProxyUpgradeHandler.Events>()

        let setup = try setupHTTPProxy(builder: { (c, h, headers) -> EventLoopFuture<HTTPHeaders> in
            c.eventLoop.makeSucceededFuture(headers)
        }, upgrade: { (c, h) -> EventLoopFuture<Void> in
            XCTAssertTrue(record.events.isEmpty)
            return c.channel.eventLoop.makeSucceededFuture(())
        }, extraHTTPHandlers: [record], completion: { (c) in
            c.close(promise: nil)
        })
        
        defer {
            XCTAssertNoThrow(try setup.eventLoopGroup.syncShutdownGracefully())
        }

        let completePromise = setup.eventLoopGroup.next().makePromise(of: Void.self)
        let clientHandler = ArrayAccumulationHandler<ByteBuffer> { buffers in
            let resultString = buffers.map { $0.getString(at: $0.readerIndex, length: $0.readableBytes)! }.joined(separator: "")
            assert(resultString,
                           expectedLine: "HTTP/1.1 200 OK",
                           expectedHTTPHeaders: ["connection: established"])
            completePromise.succeed(())
        }

        XCTAssertNoThrow(try setup.client.pipeline.addHandler(clientHandler).wait())

        // This request is safe to upgrade.
        let request = "CONNECT * HTTP/1.1\r\nHost: localhost\r\n\r\n"
        XCTAssertNoThrow(try setup.client.writeAndFlush(NIOAny(ByteBuffer.writeString(request))).wait())

        // Let the machinery do its thing.
        XCTAssertNoThrow(try completePromise.futureResult.wait())

        // At this time we should have received one user event. We schedule this onto the
        // event loop to guarantee thread safety.
        XCTAssertNoThrow(try setup.extra.eventLoop.scheduleTask(deadline: .now()) {
            XCTAssertEqual(record.events.count, 1)
            if case .success(let head) = record.events[0] {
                XCTAssertEqual(head.method, .CONNECT)
                XCTAssertEqual(head.uri, "*")
                XCTAssertEqual(head.version, HTTPVersion(major: 1, minor: 1))
            } else {
                XCTFail("Unexpected event: \(record.events[0])")
            }
            }.futureResult.wait())

        // We also want to confirm that the upgrade handler is no longer in the pipeline.
        try setup.extra.pipeline.waitForUpgraderToBeRemoved()
    }
}
