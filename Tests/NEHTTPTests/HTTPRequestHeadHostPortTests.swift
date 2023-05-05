//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2023 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import XCTest

@testable import NEHTTP

final class HTTPRequestHeadHostPortTests: XCTestCase {

  func testGetTheHostAndPortFromTheRequestHeadWhoseHostFieldContainsBothHostnameAndPort() {
    let head = HTTPRequestHead(
      version: .http1_1,
      method: .CONNECT,
      uri: "swift.org:443",
      headers: ["Host": "swift.org:443"]
    )
    XCTAssertEqual(head.host, "swift.org")
    XCTAssertEqual(head.port, 443)
  }

  func testGetTheHostAndPortFromTheRequestHeadWhoseHostFieldOnlyContainsHostname() {
    let head = HTTPRequestHead(
      version: .http1_1,
      method: .CONNECT,
      uri: "swift.org:443",
      headers: ["Host": "swift.org"]
    )
    XCTAssertEqual(head.host, "swift.org")
    XCTAssertEqual(head.port, 443)
  }

  func testGetTheHostAndPortFromTheRequestHeadWhoseHostFieldIsMissing() {
    let head = HTTPRequestHead(version: .http1_1, method: .CONNECT, uri: "swift.org:443")
    XCTAssertEqual(head.host, "swift.org")
    XCTAssertEqual(head.port, 443)
  }

  func testGetPortFromTheRequestHeadContainingOnlyTheHostnameInBothURIAndHostField() {
    let head = HTTPRequestHead(version: .http1_1, method: .CONNECT, uri: "swift.org")
    XCTAssertEqual(head.port, 80)
  }
}
