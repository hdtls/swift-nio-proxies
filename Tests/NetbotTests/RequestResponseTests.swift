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
@testable import Netbot

final class RequestResponseTests: XCTestCase {
    
    func testRequestInitialize() {
        let id = UUID()
        let request = Request(id: id, head: .init(version: .http1_1, method: .GET, uri: "uri", headers: .init()))
        XCTAssertEqual(request.httpMethod, .GET)
        XCTAssertEqual(request.httpVersion, .http1_1)
        XCTAssertEqual(request.url, URL(string: "uri"))
        XCTAssertEqual(request.httpHeaders, .init())
        XCTAssertNil(request.httpBody)
        XCTAssertEqual(request.id, id)
    }
    
    func testResponseInitialize() {
        let response = Response(head: .init(version: .http1_1, status: .ok, headers: .init()))
        XCTAssertEqual(response.httpVersion, .http1_1)
        XCTAssertEqual(response.status, .ok)
        XCTAssertEqual(response.httpHeaders, .init())
        XCTAssertNil(response.httpBody)
    }
    
    func testReqeustCodable() throws {
        let expected = Request(head: .init(version: .http1_1, method: .GET, uri: "uri", headers: .init([("Accept", "application/json")])))
        let data = try JSONEncoder().encode(expected)
        let req = try JSONDecoder().decode(Request.self, from: data)
        
        XCTAssertEqual(req, expected)
    }
    
    func testResponseCodable() throws {
        let expected = Response(head: .init(version: .http1_1, status: .ok, headers: .init()))
        let data = try JSONEncoder().encode(expected)
        let response = try JSONDecoder().decode(Response.self, from: data)
        
        XCTAssertEqual(response, expected)
    }
    
    func testRequestDecoding() throws {
        let expected = Request(head: .init(version: .http1_1, method: .GET, uri: "uri", headers: .init([("Accept", "application/json")])))
    
        let json: [String : Any] = [
            "status": [
                "statusCode": 200,
                "resonPhrase": "OK"
            ],
            "id": "\(expected.id)",
            "url": "uri",
            "httpVersion": "1.1",
            "httpMethod": "GET",
            "httpHeaders": ["Accept: application/json"]
        ]

        let data = try JSONSerialization.data(withJSONObject: json, options: .fragmentsAllowed)
        let request = try JSONDecoder().decode(Request.self, from: data)
        XCTAssertEqual(request, expected)
    }
}
