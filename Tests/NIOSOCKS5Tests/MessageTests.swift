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

class MessageTests: XCTestCase {

    func testAuthenticationMethodRequestReadWrite() throws {
        let expected = Authentication.Method.Request(methods: [.noRequired, .usernamePassword])
        var buffer = ByteBuffer()
        buffer.writeAuthenticationMethodRequest(expected)
        let req = try buffer.readAuthenticationMethodRequest()

        XCTAssertEqual(req?.version, expected.version)
        XCTAssertEqual(req?.methods, expected.methods)
    }

    func testAuthenticationMethodResponseReadWrite() throws {
        let expected = Authentication.Method.Response(method: .usernamePassword)
        var buffer = ByteBuffer()
        buffer.writeAuthenticationMethodResponse(expected)
        let response = try buffer.readAuthenticationMethodResponse()

        XCTAssertEqual(response?.version, expected.version)
        XCTAssertEqual(response?.method, expected.method)
    }

    func testAuthenticationRequestReadWrite() throws {
        let expected = Authentication.UsernameAuthenticationRequest(
            username: "username",
            password: "password"
        )
        var buffer = ByteBuffer()
        buffer.writeAuthenticationRequest(expected)
        let req = buffer.readAuthenticationRequest()

        XCTAssertEqual(req?.version, expected.version)
        XCTAssertEqual(req?.username, expected.username)
        XCTAssertEqual(req?.password, expected.password)
    }

    func testAuthenticationResponseReadWrite() throws {
        let expected = Authentication.UsernameAuthenticationResponse(status: 0)
        var buffer = ByteBuffer()
        buffer.writeAuthenticationResponse(expected)
        let response = buffer.readAuthenticationResponse()

        XCTAssertEqual(response?.version, expected.version)
        XCTAssertEqual(response?.status, expected.status)
        XCTAssertTrue(response!.isSuccess)
    }

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
