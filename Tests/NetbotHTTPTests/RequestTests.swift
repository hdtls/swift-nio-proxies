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

class RequestTests: XCTestCase {

    func testInitialize() {
        let req = Request(head: .init(version: .http1_1, method: .GET, uri: "/", headers: [:]))
        
        XCTAssertEqual(req.httpMethod, .GET)
        XCTAssertEqual(req.uri, "/")
        XCTAssertEqual(req.httpVersion, .http1_1)
        XCTAssertEqual(req.httpHeaders, [:])
        XCTAssertEqual(req.serverHostname, "/")
        XCTAssertEqual(req.serverPort, 80)
        XCTAssertNil(req.httpBody)
    }
    
    func testShouldParseServerHostnameFromHTTPHostIfHostFieldFound() {
        let req = Request(head: .init(version: .http1_1, method: .GET, uri: "/", headers: ["Host" : "example.com"]))
        
        XCTAssertEqual(req.httpMethod, .GET)
        XCTAssertEqual(req.uri, "/")
        XCTAssertEqual(req.httpVersion, .http1_1)
        XCTAssertEqual(req.httpHeaders, ["Host" : "example.com"])
        XCTAssertEqual(req.serverHostname, "example.com")
        XCTAssertEqual(req.serverPort, 80)
        XCTAssertNil(req.httpBody)
    }
    
    func testShouldParseServerHostnameFromURIIfHostFieldNotFound() {
        let req = Request(head: .init(version: .http1_1, method: .GET, uri: "/", headers: [:]))
        
        XCTAssertEqual(req.serverHostname, "/")
    }
    
    func testShouldParsePortFromHostFirstIfHostFieldFound() {
        let req = Request(head: .init(version: .http1_1, method: .GET, uri: "/", headers: ["Host" : "example.com:8080"]))
        
        XCTAssertEqual(req.serverPort, 8080)
    }
    
    func testShouldReturnDomainPortForAddressIfServerHostnameIsNotIPAddress() throws {
        let req = Request(head: .init(version: .http1_1, method: .GET, uri: "/", headers: ["Host" : "example.com"]))
        
        switch try req.address {
            case .domainPort(let domain, let port):
                XCTAssertEqual(domain, "example.com")
                XCTAssertEqual(port, 80)
            default:
                XCTFail("Address should be domainPort because host is domain port style.")
        }
    }
        
    func testShouldReturnSocketAddressIfServerHostnameIsIPAddress() throws {
        let req = Request(head: .init(version: .http1_1, method: .GET, uri: "/", headers: ["Host" : "192.168.0.1"]))
        
        switch try req.address {
            case .socketAddress(let addr):
                XCTAssertEqual(addr, try SocketAddress(ipAddress: "192.168.0.1", port: 80))
            default:
                XCTFail("Address should be domainPort because host is domain port style.")
        }
    }
    
    func testReqeustCodable() throws {
        let expected = Request(head: .init(version: .http1_1, method: .GET, uri: "uri", headers: .init([("Accept", "application/json")])))
        let data = try JSONEncoder().encode(expected)
        let req = try JSONDecoder().decode(Request.self, from: data)
        
        XCTAssertEqual(req, expected)
    }
    
    func testRequestDecoding() throws {
        let expected = Request(head: .init(version: .http1_1, method: .GET, uri: "uri", headers: .init([("Accept", "application/json")])))
        
        let json: [String : Any] = [
            "status": [
                "statusCode": 200,
                "resonPhrase": "OK"
            ],
            "id": "\(expected.id)",
            "uri": "uri",
            "httpVersion": "1.1",
            "httpMethod": "GET",
            "httpHeaders": ["Accept: application/json"]
        ]
        
        let data = try JSONSerialization.data(withJSONObject: json, options: .fragmentsAllowed)
        let request = try JSONDecoder().decode(Request.self, from: data)
        XCTAssertEqual(request, expected)
    }
}
