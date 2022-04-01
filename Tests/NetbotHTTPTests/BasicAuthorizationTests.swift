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
        XCTAssertNil(headers.basicAuthorization)
    }
    
    func testParseBasicAuthorizationFromHTTPHeadersWitchAuthorizationFieldIsNotBasicAuthorization() {
        var headers = HTTPHeaders()
        headers.add(name: .authorization, value: "Bearer <token>")
        XCTAssertNil(headers.basicAuthorization)
    }
    
    func testParseBasicAuthorizationFromHTTPHeadersWitchAuthorizationFieldIsInvalid() {
        var headers = HTTPHeaders()
        headers.add(name: .authorization, value: "Basic <token>")
        XCTAssertNil(headers.basicAuthorization)
        
        headers.replaceOrAdd(name: .authorization, value: "Basic cGFzc3dvcmQ=")
        XCTAssertNil(headers.basicAuthorization)
    }
    
    func testParseBasicAuthorization() {
        var headers = HTTPHeaders()
        headers.add(name: .authorization, value: "Basic dGVzdDpwYXNzd29yZA==")

        XCTAssertNotNil(headers.basicAuthorization)
        
        XCTAssertEqual(headers.basicAuthorization?.username, "test")
        XCTAssertEqual(headers.basicAuthorization?.password, "password")
    }
    
    func testSetBasicAuthorizationForHTTPHeaders() {
        var headers = HTTPHeaders()
        headers.basicAuthorization = .init(username: "test", password: "password")
        XCTAssertEqual(headers.first(name: .authorization), "Basic dGVzdDpwYXNzd29yZA==")
        
        headers.basicAuthorization = .init(username: "replacePreviouse", password: "password")
        XCTAssertEqual(headers.first(name: .authorization), "Basic cmVwbGFjZVByZXZpb3VzZTpwYXNzd29yZA==")
        
        headers.basicAuthorization = nil
        XCTAssertFalse(headers.contains(name: .authorization))
    }
}
