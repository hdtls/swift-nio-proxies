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

fileprivate let domainsetString = """
apple.com
.apple.com
"""

final fileprivate class MockURLProtocol: URLProtocol {
    
    static var stubs: [URL : Data] = [:]
    static func stub(url: URL, response: Data) {
        stubs[url] = response
    }
    
    override class func canInit(with request: URLRequest) -> Bool {
        guard let url = request.url else {
            return false
        }
        return stubs[url] != nil
    }
    
    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        return request
    }
    
    override func startLoading() {
        guard let url = request.url else {
            return
        }
        
        let data: Data? = Self.stubs[url]
        
        client?.urlProtocol(self, didReceive: .init(url: url, mimeType: "text/plain", expectedContentLength: data?.count ?? -1, textEncodingName: "utf-8"), cacheStoragePolicy: .notAllowed)
        if let data = data {
            client?.urlProtocol(self, didLoad: data)
        }
        client?.urlProtocolDidFinishLoading(self)
    }
    
    override func stopLoading() {}
}

extension Rule {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.type == rhs.type
        && lhs.pattern == rhs.pattern
        && lhs.policy == rhs.policy
        && lhs.comment == rhs.comment
    }
}

extension StandardRule: Equatable {}

extension GeoIPRule: Equatable {}

extension FinalRule: Equatable {}

extension RuleCollection {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.type == rhs.type
        && lhs.pattern == rhs.pattern
        && lhs.policy == rhs.policy
        && lhs.comment == rhs.comment
        && lhs.standardRules == rhs.standardRules
    }
}

extension RuleSet: Equatable {}

extension DomainSet: Equatable {}

final class RuleTests: XCTestCase {
    
    override class func setUp() {
        URLProtocol.registerClass(MockURLProtocol.self)
        URLSession.shared.configuration.protocolClasses?.insert(MockURLProtocol.self, at: 0)
    }
    
    func testParsingStandardRule() throws {
        var stringLiteral = "DOMAIN,apple.com,DIRECT"
        var standardRule = try StandardRule.init(stringLiteral: stringLiteral)
        XCTAssertEqual(standardRule.type, .domain)
        XCTAssertEqual(standardRule.pattern, "apple.com")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertNil(standardRule.comment)
        XCTAssertEqual(standardRule, try JSONDecoder().decode(StandardRule.self, from: try JSONSerialization.data(withJSONObject: stringLiteral, options: .fragmentsAllowed)))
        
        stringLiteral = "DOMAIN-SUFFIX,apple.com,DIRECT // rule for apple."
        standardRule = try StandardRule.init(stringLiteral: stringLiteral)
        XCTAssertEqual(standardRule.type, .domainSuffix)
        XCTAssertEqual(standardRule.pattern, "apple.com")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertEqual(standardRule.comment, "rule for apple.")
        XCTAssertEqual(standardRule, try JSONDecoder().decode(StandardRule.self, from: try JSONSerialization.data(withJSONObject: stringLiteral, options: .fragmentsAllowed)))
        
        stringLiteral = "DOMAIN-SUFFIX,   apple.com, DIRECT//rule for apple."
        standardRule = try StandardRule.init(stringLiteral: stringLiteral)
        XCTAssertEqual(standardRule.type, .domainSuffix)
        XCTAssertEqual(standardRule.pattern, "apple.com")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertEqual(standardRule.comment, "rule for apple.")
        XCTAssertEqual(standardRule, try JSONDecoder().decode(StandardRule.self, from: try JSONSerialization.data(withJSONObject: stringLiteral, options: .fragmentsAllowed)))
        
        stringLiteral = "DOMAIN-KEYWORD,apple,DIRECT"
        standardRule = try StandardRule.init(stringLiteral: stringLiteral)
        XCTAssertEqual(standardRule.type, .domainKeyword)
        XCTAssertEqual(standardRule.pattern, "apple")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertNil(standardRule.comment)
        XCTAssertEqual(standardRule, try JSONDecoder().decode(StandardRule.self, from: try JSONSerialization.data(withJSONObject: stringLiteral, options: .fragmentsAllowed)))
        
        stringLiteral = "DOMAIN-KEYWORD,apple,DIRECT"
        standardRule = try StandardRule.init(stringLiteral: stringLiteral)
        XCTAssertEqual(standardRule.type, .domainKeyword)
        XCTAssertEqual(standardRule.pattern, "apple")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertNil(standardRule.comment)
        XCTAssertEqual(standardRule, try JSONDecoder().decode(StandardRule.self, from: try JSONSerialization.data(withJSONObject: stringLiteral, options: .fragmentsAllowed)))
        
        stringLiteral = "DOMAIN-KEYWORD,apple,DIRECT,will be ignored"
        standardRule = try StandardRule.init(stringLiteral: stringLiteral)
        XCTAssertEqual(standardRule.type, .domainKeyword)
        XCTAssertEqual(standardRule.pattern, "apple")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertNil(standardRule.comment)
        XCTAssertEqual(standardRule, try JSONDecoder().decode(StandardRule.self, from: try JSONSerialization.data(withJSONObject: stringLiteral, options: .fragmentsAllowed)))
    }
    
    func testParsingInvalidStandardRule() throws {
        let invalidRuleStringLiterals = [
            "apple,DIRECT",
            "DOMAIN,apple",
            "DOMAIN,apple // balabala",
            "DOMAIN,DIRECT",
            "DOMAIN,DIRECT//balabala"
        ]
        
        let decoder = JSONDecoder()
        
        try invalidRuleStringLiterals.forEach { invalidRuleStringLiteral in
            XCTAssertThrowsError(try StandardRule.init(stringLiteral: invalidRuleStringLiteral))
            let data = try JSONSerialization.data(withJSONObject: invalidRuleStringLiteral, options: .fragmentsAllowed)
            XCTAssertThrowsError(try decoder.decode(StandardRule.self, from: data))
        }
    }
    
    func testStandardRuleEncoding() throws {
        let stringLiterals = [
            "DOMAIN,apple.com,DIRECT",
            "DOMAIN-SUFFIX,apple.com,DIRECT // rule for apple.",
            "DOMAIN-KEYWORD,apple,DIRECT"
        ]
        
        let encoder = JSONEncoder()
        
        try stringLiterals.forEach {
            let standardRule = try StandardRule.init(stringLiteral: $0)
            let standardRuleStringLiteral = try JSONSerialization.jsonObject(with: try encoder.encode(standardRule), options: .fragmentsAllowed) as! String
            XCTAssertEqual(standardRuleStringLiteral, $0)
        }
        
        var standardRule = try StandardRule.init(stringLiteral: "DOMAIN-SUFFIX,   apple.com, DIRECT//rule for apple.")
        var stringLiteral = try JSONSerialization.jsonObject(with: try encoder.encode(standardRule), options: .fragmentsAllowed) as! String
        XCTAssertEqual(stringLiteral, "DOMAIN-SUFFIX,apple.com,DIRECT // rule for apple.")
        
        standardRule = try StandardRule.init(stringLiteral: "DOMAIN-KEYWORD,apple,DIRECT,will be ignored")
        stringLiteral = try JSONSerialization.jsonObject(with: try encoder.encode(standardRule), options: .fragmentsAllowed) as! String
        XCTAssertEqual(stringLiteral, "DOMAIN-KEYWORD,apple,DIRECT")
    }
    
    func testParsingGeoIPRule() throws {
        var stringLiteral = "GEOIP,CN,DIRECT"
        var geoIpRule = try GeoIPRule.init(stringLiteral: stringLiteral)
        XCTAssertEqual(geoIpRule.type, .geoip)
        XCTAssertEqual(geoIpRule.pattern, "CN")
        XCTAssertEqual(geoIpRule.policy, "DIRECT")
        XCTAssertNil(geoIpRule.comment)
        XCTAssertEqual(geoIpRule, try JSONDecoder().decode(GeoIPRule.self, from: try JSONSerialization.data(withJSONObject: stringLiteral, options: .fragmentsAllowed)))
        
        stringLiteral = "GEOIP,CN,DIRECT // balabala"
        geoIpRule = try GeoIPRule.init(stringLiteral: stringLiteral)
        XCTAssertEqual(geoIpRule.type, .geoip)
        XCTAssertEqual(geoIpRule.pattern, "CN")
        XCTAssertEqual(geoIpRule.policy, "DIRECT")
        XCTAssertEqual(geoIpRule.comment, "balabala")
        XCTAssertEqual(geoIpRule, try JSONDecoder().decode(GeoIPRule.self, from: try JSONSerialization.data(withJSONObject: stringLiteral, options: .fragmentsAllowed)))
    }
    
    func testParsingInvalidGeoIPRule() {
        let stringLiteral = "GEOIP,CN"
        XCTAssertThrowsError(try GeoIPRule.init(stringLiteral: stringLiteral))
        XCTAssertThrowsError(try JSONDecoder().decode(GeoIPRule.self, from: JSONSerialization.data(withJSONObject: stringLiteral, options: .fragmentsAllowed)))
    }
    
    func testParsingFinalRule() throws {
        var stringLiteral = "FINAL,DIRECT"
        var finalRule = try FinalRule.init(stringLiteral: stringLiteral)
        XCTAssertEqual(finalRule.type, .final)
        XCTAssertEqual(finalRule.pattern, "")
        XCTAssertEqual(finalRule.policy, "DIRECT")
        XCTAssertNil(finalRule.comment)
        XCTAssertEqual(finalRule, try JSONDecoder().decode(FinalRule.self, from: try JSONSerialization.data(withJSONObject: stringLiteral, options: .fragmentsAllowed)))
        
        stringLiteral = "FINAL,DIRECT // balabala"
        finalRule = try FinalRule.init(stringLiteral: stringLiteral)
        XCTAssertEqual(finalRule.type, .final)
        XCTAssertEqual(finalRule.pattern, "")
        XCTAssertEqual(finalRule.policy, "DIRECT")
        XCTAssertEqual(finalRule.comment, "balabala")
        XCTAssertEqual(finalRule, try JSONDecoder().decode(FinalRule.self, from: try JSONSerialization.data(withJSONObject: stringLiteral, options: .fragmentsAllowed)))
        
        stringLiteral = "FINAL,DIRECT,dns-failed"
        finalRule = try FinalRule.init(stringLiteral: stringLiteral)
        XCTAssertEqual(finalRule.type, .final)
        XCTAssertEqual(finalRule.pattern, "dns-failed")
        XCTAssertEqual(finalRule.policy, "DIRECT")
        XCTAssertNil(finalRule.comment)
        XCTAssertEqual(finalRule, try JSONDecoder().decode(FinalRule.self, from: try JSONSerialization.data(withJSONObject: stringLiteral, options: .fragmentsAllowed)))
    }
    
    func testParsingInvalidFinalRule() {
        let stringLiterals = [
            "FINAL",
            "FINA"
        ]
        
        XCTAssertNoThrow(try stringLiterals.forEach { stringLiteral in
            XCTAssertThrowsError(try FinalRule.init(stringLiteral: stringLiteral))
            XCTAssertThrowsError(try JSONDecoder().decode(FinalRule.self, from: JSONSerialization.data(withJSONObject: stringLiteral, options: .fragmentsAllowed)))
        })
    }
    
    func testFinalRuleEncoding() throws {
        var expected = "FINAL,DIRECT"
        var finalRule = try FinalRule.init(stringLiteral: expected)
        var stringLiteral = try JSONSerialization.jsonObject(with: JSONEncoder().encode(finalRule), options: .fragmentsAllowed) as! String
        XCTAssertEqual(stringLiteral, expected)
        
        expected = "FINAL,DIRECT,dns-failed"
        finalRule = try FinalRule.init(stringLiteral: expected)
        stringLiteral = try JSONSerialization.jsonObject(with: JSONEncoder().encode(finalRule), options: .fragmentsAllowed) as! String
        XCTAssertEqual(stringLiteral, expected)
    }
    
    func testRuleSetCncoding() throws {
        let text = """
DOMAIN,apple.com
DOMAIN-SUFFIX,apple.com
DOMAIN-KEYWORD,apple
"""
        
        let expectation = self.expectation(description: "RULE-SET")
        MockURLProtocol.stub(url: .init(string: "https://ruleset")!, response: text.data(using: .utf8)!)
        let stringLiteral = "RULE-SET,https://ruleset,DIRECT"
        let ruleset = try RuleSet.init(stringLiteral: stringLiteral)
        XCTAssertEqual(ruleset.type, .ruleSet)
        XCTAssertEqual(ruleset.pattern, "https://ruleset")
        XCTAssertEqual(ruleset.policy, "DIRECT")
        XCTAssertNil(ruleset.comment)
        
        // wait for 1 seconds for mock execute.
        DispatchQueue.global().asyncAfter(deadline: .now() + 1) {
            expectation.fulfill()
        }
        waitForExpectations(timeout: 5, handler: nil)
        XCTAssertEqual(ruleset.standardRules, try text.components(separatedBy: "\n").map { try StandardRule.init(stringLiteral: $0 + ",DIRECT") })
    
        XCTAssertEqual(try JSONSerialization.jsonObject(with: try JSONEncoder().encode(ruleset), options: .fragmentsAllowed) as? String, stringLiteral)
    }
    
    func testDomainSetCoding() throws {
        let text = """
test.com
.apple.com
"""
        let expectation = self.expectation(description: "DOMAIN-SET")
        MockURLProtocol.stub(url: .init(string: "https://domainset")!, response: text.data(using: .utf8)!)
        let stringLiteral = "DOMAIN-SET,https://domainset,DIRECT"
        let domainset = try DomainSet.init(stringLiteral: stringLiteral)
        XCTAssertEqual(domainset.type, .domainSet)
        XCTAssertEqual(domainset.pattern, "https://domainset")
        XCTAssertEqual(domainset.policy, "DIRECT")
        XCTAssertNil(domainset.comment)
        
        // wait for 1 seconds for mock execute.
        DispatchQueue.global().asyncAfter(deadline: .now() + 1) {
            expectation.fulfill()
        }
        waitForExpectations(timeout: 5, handler: nil)
        XCTAssertEqual(domainset.standardRules, try text.components(separatedBy: "\n").map { try StandardRule.init(stringLiteral: "DOMAIN-SUFFIX,\($0),DIRECT") })
        
        XCTAssertEqual(try JSONSerialization.jsonObject(with: try JSONEncoder().encode(domainset), options: .fragmentsAllowed) as? String, stringLiteral)
    }
    
    func testParsingAnyRule() throws {
        func assertUnderliyingRule<T: Rule & Equatable>(_ stringLiteral: String, _ type: T.Type) throws {
            let expected = try AnyRule.init(stringLiteral: stringLiteral)
            if let rule = expected.underlying as? T {
                XCTAssertEqual(rule, try T.init(stringLiteral: stringLiteral))
            } else {
                XCTFail()
            }
        }
        
        try assertUnderliyingRule("DOMAIN,apple.com,DIRECT", StandardRule.self)
        try assertUnderliyingRule("DOMAIN-SUFFIX,apple.com,DIRECT", StandardRule.self)
        try assertUnderliyingRule("DOMAIN-KEYWORD,apple.com,DIRECT", StandardRule.self)
        try assertUnderliyingRule("FINAL,DIRECT", FinalRule.self)
        try assertUnderliyingRule("GEOIP,CN,DIRECT", GeoIPRule.self)
        
        
        let expected = try RuleSet.init(stringLiteral: "RULE-SET,https://ruleset,DIRECT")
        let actual = try AnyRule.init(stringLiteral: "RULE-SET,https://ruleset,DIRECT")
        
        let expected1 = try DomainSet.init(stringLiteral: "DOMAIN-SET,https://domainset,DIRECT")
        let actual1 = try AnyRule.init(stringLiteral: "DOMAIN-SET,https://domainset,DIRECT")
        
        let expectation = expectation(description: "ANY-RULE")
        // wait for 1 seconds for mock execute.
        DispatchQueue.global().asyncAfter(deadline: .now() + 1) {
            expectation.fulfill()
        }
        waitForExpectations(timeout: 5, handler: nil)
        
        if let rule = actual.underlying as? RuleSet {
            XCTAssertEqual(rule, expected)
        } else {
            XCTFail()
        }
        
        if let rule = actual1.underlying as? DomainSet {
            XCTAssertEqual(rule, expected1)
        } else {
            XCTFail()
        }
    }
}
