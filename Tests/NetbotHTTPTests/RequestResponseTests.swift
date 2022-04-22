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

@testable import NetbotHTTP

final class RequestResponseTests: XCTestCase {

    func testResponseInitialize() {
        let response = Response(head: .init(version: .http1_1, status: .ok, headers: .init()))
        XCTAssertEqual(response.httpVersion, .http1_1)
        XCTAssertEqual(response.status, .ok)
        XCTAssertEqual(response.httpHeaders, .init())
        XCTAssertNil(response.httpBody)
    }

    func testResponseCodable() throws {
        let expected = Response(head: .init(version: .http1_1, status: .ok, headers: .init()))
        let data = try JSONEncoder().encode(expected)
        let response = try JSONDecoder().decode(Response.self, from: data)

        XCTAssertEqual(response, expected)
    }
}
