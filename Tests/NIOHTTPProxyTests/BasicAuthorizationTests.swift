//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2021 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOHTTP1
import XCTest

@testable import NIOHTTPProxy

class BasicAuthorizationTests: XCTestCase {

    func testParseBasicAuthorizationFromHTTPHeadersWithoutAuthorizationField() {
        let headers = HTTPHeaders()
        XCTAssertNil(headers.proxyBasicAuthorization)
    }

    func testParseBasicAuthorizationFromHTTPHeadersWitchAuthorizationFieldIsNotBasicAuthorization()
    {
        var headers = HTTPHeaders()
        headers.add(name: .proxyAuthorization, value: "Bearer <token>")
        XCTAssertNil(headers.proxyBasicAuthorization)
    }

    func testParseBasicAuthorizationFromHTTPHeadersWitchAuthorizationFieldIsInvalid() {
        var headers = HTTPHeaders()
        headers.add(name: .proxyAuthorization, value: "Basic <token>")
        XCTAssertNil(headers.proxyBasicAuthorization)

        headers.replaceOrAdd(name: .proxyAuthorization, value: "Basic cGFzc3dvcmQ=")
        XCTAssertNil(headers.proxyBasicAuthorization)
    }

    func testParseBasicAuthorization() {
        var headers = HTTPHeaders()
        headers.add(name: .proxyAuthorization, value: "Basic dGVzdDpwYXNzd29yZA==")

        XCTAssertNotNil(headers.proxyBasicAuthorization)

        XCTAssertEqual(headers.proxyBasicAuthorization?.username, "test")
        XCTAssertEqual(headers.proxyBasicAuthorization?.password, "password")
    }

    func testSetBasicAuthorizationForHTTPHeaders() {
        var headers = HTTPHeaders()
        headers.proxyBasicAuthorization = .init(username: "test", password: "password")
        XCTAssertEqual(headers.first(name: .proxyAuthorization), "Basic dGVzdDpwYXNzd29yZA==")

        headers.proxyBasicAuthorization = .init(username: "replacePreviouse", password: "password")
        XCTAssertEqual(
            headers.first(name: .proxyAuthorization),
            "Basic cmVwbGFjZVByZXZpb3VzZTpwYXNzd29yZA=="
        )

        headers.proxyBasicAuthorization = nil
        XCTAssertFalse(headers.contains(name: .proxyAuthorization))
    }
}
