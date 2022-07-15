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

@testable import NIOSOCKS5

class ModelsTests: XCTestCase {

    func testRequestReadWrite() {
        var request = Request.init(command: .connect, address: .domainPort("localhost", 80))
        var buffer = ByteBuffer()
        buffer.writeRequestDetails(request)
        XCTAssertNoThrow(XCTAssertEqual(try buffer.readRequestDetails(), request))

        request = .init(
            command: .bind,
            address: .socketAddress(try! .init(ipAddress: "127.0.0.1", port: 80))
        )
        buffer.writeRequestDetails(request)
        XCTAssertNoThrow(XCTAssertEqual(try buffer.readRequestDetails(), request))

        request = .init(
            command: .udpAssociate,
            address: .socketAddress(try! .init(ipAddress: "::1", port: 80))
        )
        buffer.writeRequestDetails(request)
        XCTAssertNoThrow(XCTAssertEqual(try buffer.readRequestDetails(), request))
    }

    func testResponseReadWrite() {
        let response = Response.init(reply: .succeeded, boundAddress: .domainPort("localhost", 80))
        var buffer = ByteBuffer()
        buffer.writeServerResponse(response)
        XCTAssertNoThrow(XCTAssertEqual(try buffer.readServerResponse(), response))
    }
}
