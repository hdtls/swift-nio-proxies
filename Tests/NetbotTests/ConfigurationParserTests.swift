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

class ConfigFileParsingTests: XCTestCase {
    
    func testParsingRuleWithoutComment() throws {
        let literal = "DOMAIN,www.github.com,DIRECT"
        let rule = try Rule.init(string: literal)

        XCTAssertEqual(rule.type, .domain)
        XCTAssertEqual(rule.pattern, "www.github.com")
        XCTAssertEqual(rule.policy, "DIRECT")
        XCTAssertNil(rule.comment)
    }
    
    func testParsingRuleWithComment() throws {
        let literal = "DOMAIN,www.github.com,DIRECT // The rule for Github."
        let rule = try Rule.init(string: literal)

        XCTAssertEqual(rule.type, .domain)
        XCTAssertEqual(rule.pattern, "www.github.com")
        XCTAssertEqual(rule.policy, "DIRECT")
        XCTAssertEqual(rule.comment, "The rule for Github.")
    }
    
    func testParsingRuleWithInvalidStatements() {
        let literal = "DOMAIN,www.github.com"
        XCTAssertThrowsError(try Rule.init(string: literal))
    }
    
    func testParsingFinalRule() {
        let literal = "FINAL,DIRECT"
        let rule: Rule = try! Rule.init(string: literal)
        XCTAssertEqual(rule.type, .final)
        XCTAssertEqual(rule.policy, "DIRECT")
        XCTAssertNil(rule.pattern)
        XCTAssertNil(rule.comment)
    }
    
    func testParsingFinalRuleWithComment() {
        let literal = "FINAL,DIRECT // The rule for FINAL."
        let rule: Rule = try! Rule.init(string: literal)
        XCTAssertEqual(rule.type, .final)
        XCTAssertEqual(rule.policy, "DIRECT")
        XCTAssertNil(rule.pattern)
        XCTAssertEqual(rule.comment, "The rule for FINAL.")
    }
    
    func testRuleEncoding() throws {
        let expect = "DOMAIN,www.github.com,DIRECT // The rule for Github."
        let rule = try Rule.init(string: expect)
        let data = try JSONEncoder().encode(rule)
        
        let result = try JSONSerialization.jsonObject(with: data, options: .fragmentsAllowed) as! String
        
        XCTAssertEqual(result, expect)
    }
    
    func testFinalRuleEncoding() throws {
        let expect = "FINAL,DIRECT // The rule for FINAL."
        let rule = try Rule.init(string: expect)
        let data = try JSONEncoder().encode(rule)
        
        let result = try JSONSerialization.jsonObject(with: data, options: .fragmentsAllowed) as! String
        
        XCTAssertEqual(result, expect)
    }
    
    func testReplicaEncoding() throws {
        let expect = ReplicaConfiguration(hideAppleRequests: true, hideCrashlyticsRequests: false, hideCrashReporterRequests: true, hideUDP: true, reqMsgFilterType: .none, reqMsgFilter: "github.com")
        
        let data = try JSONEncoder().encode(expect)
        let result = try JSONDecoder().decode(ReplicaConfiguration.self, from: data)
        
        XCTAssertEqual(result, expect)
    }
}
