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
import XCTest

@testable import NIOSOCKS5

class ClientGreetingTests: XCTestCase {

    func testReadFromByteBuffer() {
        var buffer = ByteBuffer()
        buffer.writeBytes([0x05, 0x01, 0x00])
        let clientGreeting = try! buffer.readAuthenticationMethodRequest()
        XCTAssertEqual(clientGreeting, .init(methods: [.noRequired]))
        XCTAssertEqual(buffer.readableBytes, 0)

        buffer.writeBytes([0x05, 0x03, 0x00, 0x01, 0x02])
        XCTAssertNoThrow(
            XCTAssertEqual(
                try buffer.readClientGreeting(),
                .init(methods: [.noRequired, .gssapi, .usernamePassword])
            )
        )
        XCTAssertEqual(buffer.readableBytes, 0)
    }

    func testWriteToByteBuffer() {
        let clientGreeting = Authentication.Method.Request.init(methods: [.noRequired])
        var buffer = ByteBuffer()
        XCTAssertEqual(buffer.writeAuthenticationMethodRequest(clientGreeting), 3)
        XCTAssertEqual(buffer.readableBytes, 3)
        XCTAssertEqual(buffer.readBytes(length: 3), [0x05, 0x01, 0x00])

        buffer.writeAuthenticationMethodRequest(
            .init(methods: [.noRequired, .gssapi, .usernamePassword])
        )
        XCTAssertEqual(buffer.readableBytes, 5)
        XCTAssertEqual(buffer.readBytes(length: 5), [0x05, 0x03, 0x00, 0x01, 0x02])
    }
}
