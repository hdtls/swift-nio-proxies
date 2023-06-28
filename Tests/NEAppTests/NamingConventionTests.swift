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

@testable import NEApp

final class NamingConventionTests: XCTestCase {

  func testConvertProfileFieldNameToKebabCase() {
    XCTAssertEqual("dnsServers".convertToKebabCase(), "dns-servers")
    XCTAssertEqual("basicSettings".convertToKebabCase(), "[General]")
    XCTAssertEqual("routingRules".convertToKebabCase(), "[Rule]")
    XCTAssertEqual("policies".convertToKebabCase(), "[Policies]")
    XCTAssertEqual("policyGroups".convertToKebabCase(), "[Policy Group]")
    XCTAssertEqual("manInTheMiddleSettings".convertToKebabCase(), "[MitM]")
  }

  func testConvertProfileFieldNameToCamelCase() {
    XCTAssertEqual("dns-servers".convertToCamelCase(), "dnsServers")
    XCTAssertEqual("[General]".convertToCamelCase(), "basicSettings")
    XCTAssertEqual("[Rule]".convertToCamelCase(), "routingRules")
    XCTAssertEqual("[Policies]".convertToCamelCase(), "policies")
    XCTAssertEqual("[Policy Group]".convertToCamelCase(), "policyGroups")
    XCTAssertEqual("[MitM]".convertToCamelCase(), "manInTheMiddleSettings")
  }
}
