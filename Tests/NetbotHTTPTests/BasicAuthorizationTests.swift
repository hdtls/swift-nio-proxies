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
import NIOHTTP1
@testable import NetbotHTTP

class BasicAuthorizationTests: XCTestCase {

    func testParseBasicAuthorizationFromHTTPHeadersWithoutAuthorizationField() {
        let headers = HTTPHeaders()
        XCTAssertNil(headers.proxyBasicAuthorization)
    }
    
    func testParseBasicAuthorizationFromHTTPHeadersWitchAuthorizationFieldIsNotBasicAuthorization() {
        var headers = HTTPHeaders()
        headers.add(name: .authorization, value: "Bearer <token>")
        XCTAssertNil(headers.proxyBasicAuthorization)
    }
    
    func testParseBasicAuthorizationFromHTTPHeadersWitchAuthorizationFieldIsInvalid() {
        var headers = HTTPHeaders()
        headers.add(name: .authorization, value: "Basic <token>")
        XCTAssertNil(headers.proxyBasicAuthorization)
        
        headers.replaceOrAdd(name: .authorization, value: "Basic cGFzc3dvcmQ=")
        XCTAssertNil(headers.proxyBasicAuthorization)
    }
    
    func testParseBasicAuthorization() {
        var headers = HTTPHeaders()
        headers.add(name: .authorization, value: "Basic dGVzdDpwYXNzd29yZA==")

        XCTAssertNotNil(headers.proxyBasicAuthorization)
        
        XCTAssertEqual(headers.proxyBasicAuthorization?.username, "test")
        XCTAssertEqual(headers.proxyBasicAuthorization?.password, "password")
    }
    
    func testSetBasicAuthorizationForHTTPHeaders() {
        var headers = HTTPHeaders()
        headers.proxyBasicAuthorization = .init(username: "test", password: "password")
        XCTAssertEqual(headers.first(name: .proxyAuthorization), "Basic dGVzdDpwYXNzd29yZA==")
        
        headers.proxyBasicAuthorization = .init(username: "replacePreviouse", password: "password")
        XCTAssertEqual(headers.first(name: .proxyAuthorization), "Basic cmVwbGFjZVByZXZpb3VzZTpwYXNzd29yZA==")
        
        headers.proxyBasicAuthorization = nil
        XCTAssertFalse(headers.contains(name: .authorization))
    }
}
