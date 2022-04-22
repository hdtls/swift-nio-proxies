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
import XCTest

@testable import NetbotHTTP

class HTTPProxyClientHandlerTests: XCTestCase {

    var channel: EmbeddedChannel!
    var handler: HTTP1ClientCONNECTTunnelHandler!

    func connect() {
        try! self.channel.connect(to: .init(ipAddress: "127.0.0.1", port: 80)).wait()
    }

    override func setUpWithError() throws {
        XCTAssertNil(self.channel)

        self.handler = .init(
            logger: .init(label: ""),
            destinationAddress: .socketAddress(try .init(ipAddress: "127.0.0.1", port: 8080))
        )
        self.channel = EmbeddedChannel(handler: self.handler)
    }

    override func tearDownWithError() throws {
        XCTAssertNotNil(self.channel)
        self.channel = nil
    }

    func assertHTTPPart(_ httpPart: HTTPClientRequestPart?, line: UInt = #line) throws {
        let part = try self.channel.readOutbound(as: HTTPClientRequestPart.self)
        XCTAssertEqual(part, httpPart, line: line)
    }

    func testDelayedConnection() throws {
        XCTAssertNil(try self.channel.readOutbound())

        self.connect()

        try assertHTTPPart(.head(.init(version: .http1_1, method: .CONNECT, uri: "127.0.0.1:8080")))

        try assertHTTPPart(.end(nil))
    }

    func testDelayedHandlerAdded() throws {
        XCTAssertNoThrow(try self.channel.close().wait())

        self.channel = EmbeddedChannel()
        XCTAssertNoThrow(
            try self.channel.connect(to: .init(ipAddress: "127.0.0.1", port: 80)).wait()
        )
        XCTAssertTrue(self.channel.isActive)

        XCTAssertNil(try self.channel.readOutbound())

        XCTAssertNoThrow(self.channel.pipeline.addHandler(self.handler))

        try assertHTTPPart(.head(.init(version: .http1_1, method: .CONNECT, uri: "127.0.0.1:8080")))

        try assertHTTPPart(.end(nil))
    }
}
