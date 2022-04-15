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
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

private class MockURLProtocol: URLProtocol {
    
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

final class RuleTests: XCTestCase {
    
    override class func setUp() {
        _ = URLProtocol.registerClass(MockURLProtocol.self)
        URLSession.shared.configuration.protocolClasses?.insert(MockURLProtocol.self, at: 0)
    }
    
    func testParsingDomainRule() throws {
        let string = "DOMAIN,swift.org,DIRECT"
        let standardRule = try AnyRule.init(string: string)
        XCTAssertEqual(standardRule.type, .domain)
        XCTAssertEqual(standardRule.expression, "swift.org")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertEqual(standardRule.comment, "")
    }
    
    func testParsingDomainRuleWithComment() throws {
        let string = "DOMAIN,swift.org,DIRECT // this is rule comment."
        let standardRule = try AnyRule.init(string: string)
        XCTAssertEqual(standardRule.type, .domain)
        XCTAssertEqual(standardRule.expression, "swift.org")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertEqual(standardRule.comment, "this is rule comment.")
    }
    
    func testAppropriateErrorWhenParsingDomainRuleWithInvalidSchema() {
        let string = "invalidSchema,swift.org,DIRECT // this is rule comment."
        
        XCTAssertThrowsError(try AnyRule.init(string: string)) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .unsupported))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
    }
    
    func testAppropriateErrorWhenParsingDomainRuleWithMissingFieldRuleString() {
        XCTAssertThrowsError(try AnyRule.init(string: "DOMAIN,swift.org")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .missingField))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
    }
    
    func testDomainRuleCoding() throws {
        let jsonString = "DOMAIN,swift.org,DIRECT // this is rule comment."
        var data: Data!
        XCTAssertNoThrow(data = try JSONSerialization.data(withJSONObject: jsonString, options: .fragmentsAllowed))
        XCTAssertNotNil(data)
        
        var standardRule: AnyRule!
        XCTAssertNoThrow(standardRule = try JSONDecoder().decode(AnyRule.self, from: data))
        XCTAssertNotNil(standardRule)
        XCTAssertEqual(standardRule.type, .domain)
        XCTAssertEqual(standardRule.expression, "swift.org")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertEqual(standardRule.comment, "this is rule comment.")
        
        var string: String!
        XCTAssertNoThrow(string = try JSONSerialization.jsonObject(with: JSONEncoder().encode(standardRule), options: .fragmentsAllowed) as? String)
        XCTAssertNotNil(string)
        XCTAssertEqual(string, jsonString)
    }
    
    func testParsingDomainSuffixRule() throws {
        let string = "DOMAIN-SUFFIX,swift.org,DIRECT"
        let standardRule = try AnyRule.init(string: string)
        XCTAssertEqual(standardRule.type, .domainSuffix)
        XCTAssertEqual(standardRule.expression, "swift.org")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertEqual(standardRule.comment, "")
    }
    
    func testParsingDomainSuffixRuleWithComment() throws {
        let string = "DOMAIN-SUFFIX,swift.org,DIRECT // this is rule comment."
        let standardRule = try AnyRule.init(string: string)
        XCTAssertEqual(standardRule.type, .domainSuffix)
        XCTAssertEqual(standardRule.expression, "swift.org")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertEqual(standardRule.comment, "this is rule comment.")
    }
    
    func testAppropriateErrorWhenParsingDomainSuffixRuleWithInvalidSchema() {
        let string = "invalidSchema,swift.org,DIRECT // this is rule comment."
        
        XCTAssertThrowsError(try AnyRule.init(string: string)) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .unsupported))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
    }
    
    func testAppropriateErrorWhenParsingDomainSuffixRuleWithMissingFieldRuleString() {
        XCTAssertThrowsError(try AnyRule.init(string: "DOMAIN-SUFFIX,swift.org")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .missingField))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
    }
    
    func testDomainSuffixRuleCoding() throws {
        let jsonString = "DOMAIN-SUFFIX,swift.org,DIRECT // this is rule comment."
        var data: Data!
        XCTAssertNoThrow(data = try JSONSerialization.data(withJSONObject: jsonString, options: .fragmentsAllowed))
        XCTAssertNotNil(data)
        
        var standardRule: AnyRule!
        XCTAssertNoThrow(standardRule = try JSONDecoder().decode(AnyRule.self, from: data))
        XCTAssertNotNil(standardRule)
        XCTAssertEqual(standardRule.type, .domainSuffix)
        XCTAssertEqual(standardRule.expression, "swift.org")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertEqual(standardRule.comment, "this is rule comment.")
        
        var string: String!
        XCTAssertNoThrow(string = try JSONSerialization.jsonObject(with: JSONEncoder().encode(standardRule), options: .fragmentsAllowed) as? String)
        XCTAssertNotNil(string)
        XCTAssertEqual(string, jsonString)
    }
    
    func testParsingDomainKeywordRule() throws {
        let string = "DOMAIN-KEYWORD,swift.org,DIRECT"
        let standardRule = try AnyRule.init(string: string)
        XCTAssertEqual(standardRule.type, .domainKeyword)
        XCTAssertEqual(standardRule.expression, "swift.org")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertEqual(standardRule.comment, "")
    }
    
    func testParsingDomainKeywordRuleWithComment() throws {
        let string = "DOMAIN-KEYWORD,swift.org,DIRECT // this is rule comment."
        let standardRule = try AnyRule.init(string: string)
        XCTAssertEqual(standardRule.type, .domainKeyword)
        XCTAssertEqual(standardRule.expression, "swift.org")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertEqual(standardRule.comment, "this is rule comment.")
    }
    
    func testAppropriateErrorWhenParsingDomainKeywordRuleWithInvalidSchema() {
        let string = "invalidSchema,swift.org,DIRECT // this is rule comment."
        
        XCTAssertThrowsError(try AnyRule.init(string: string)) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .unsupported))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
    }
    
    func testAppropriateErrorWhenParsingDomainKeywordRuleWithMissingFieldRuleString() {
        XCTAssertThrowsError(try AnyRule.init(string: "DOMAIN-KEYWORD,swift.org")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .missingField))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
    }
    
    func testDomainKeywordRuleCoding() throws {
        let jsonString = "DOMAIN-KEYWORD,swift.org,DIRECT // this is rule comment."
        var data: Data!
        XCTAssertNoThrow(data = try JSONSerialization.data(withJSONObject: jsonString, options: .fragmentsAllowed))
        XCTAssertNotNil(data)
        
        var standardRule: AnyRule!
        XCTAssertNoThrow(standardRule = try JSONDecoder().decode(AnyRule.self, from: data))
        XCTAssertNotNil(standardRule)
        XCTAssertEqual(standardRule.type, .domainKeyword)
        XCTAssertEqual(standardRule.expression, "swift.org")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertEqual(standardRule.comment, "this is rule comment.")
        
        var string: String!
        XCTAssertNoThrow(string = try JSONSerialization.jsonObject(with: JSONEncoder().encode(standardRule), options: .fragmentsAllowed) as? String)
        XCTAssertNotNil(string)
        XCTAssertEqual(string, jsonString)
    }
    
    func testParsingDomainSet() throws {
        let string = "DOMAIN-SET,http://domainset.com,DIRECT"
        let standardRule = try AnyRule.init(string: string)
        XCTAssertEqual(standardRule.type, .domainSet)
        XCTAssertEqual(standardRule.expression, "http://domainset.com")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertEqual(standardRule.comment, "")
    }
    
    func testParsingDomainSetWithComment() throws {
        let string = "DOMAIN-SET,http://domainset.com,DIRECT // this is rule comment."
        let standardRule = try AnyRule.init(string: string)
        XCTAssertEqual(standardRule.type, .domainSet)
        XCTAssertEqual(standardRule.expression, "http://domainset.com")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertEqual(standardRule.comment, "this is rule comment.")
    }
    
    func testAppropriateErrorWhenParsingDomainSetWithInvalidSchema() {
        let string = "invalidSchema,http://domainset.com,DIRECT // this is rule comment."
        
        XCTAssertThrowsError(try AnyRule.init(string: string)) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .unsupported))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
    }
    
    func testAppropriateErrorWhenParsingDomainSetWithMissingFieldRuleString() {
        XCTAssertThrowsError(try AnyRule.init(string: "DOMAIN-SET,http://domainset.com")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .missingField))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
    }
    
    #if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
    func testDomainSetCoding() throws {
        let text = """
swift.org
.apple.com
"""
        
        let expectation = self.expectation(description: "DOMAIN-SET")
        MockURLProtocol.stub(url: .init(string: "http://domainset.com")!, response: text.data(using: .utf8)!)
        let string = "DOMAIN-SET,http://domainset.com,DIRECT"
        let domainset = try AnyRule(string: string)
        domainset.performExternalResourcesLoading { _ in
            expectation.fulfill()
        }
        waitForExpectations(timeout: 15, handler: nil)
        
        XCTAssertEqual(domainset.expression, "http://domainset.com")
        XCTAssertEqual(domainset.policy, "DIRECT")
        XCTAssertEqual(domainset.comment, "")
        XCTAssertEqual(try JSONSerialization.jsonObject(with: try JSONEncoder().encode(domainset), options: .fragmentsAllowed) as? String, string)
    }
    #endif
    
    func testParsingGeoIPRule() throws {
        let string = "GEOIP,swift.org,DIRECT"
        let standardRule = try AnyRule.init(string: string)
        XCTAssertEqual(standardRule.type, .geoIp)
        XCTAssertEqual(standardRule.expression, "swift.org")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertEqual(standardRule.comment, "")
    }
    
    func testParsingGeoIPRuleWithComment() throws {
        let string = "GEOIP,swift.org,DIRECT // this is rule comment."
        let standardRule = try AnyRule.init(string: string)
        XCTAssertEqual(standardRule.type, .geoIp)
        XCTAssertEqual(standardRule.expression, "swift.org")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertEqual(standardRule.comment, "this is rule comment.")
    }
    
    func testAppropriateErrorWhenParsingGeoIPRuleWithInvalidSchema() {
        let string = "invalidSchema,swift.org,DIRECT // this is rule comment."
        
        XCTAssertThrowsError(try AnyRule.init(string: string)) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .unsupported))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
    }
    
    func testAppropriateErrorWhenParsingGeoIPRuleWithMissingFieldRuleString() {
        XCTAssertThrowsError(try AnyRule.init(string: "GEOIP,swift.org")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .missingField))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
    }
    
    func testGeoIPRuleCoding() throws {
        let jsonString = "GEOIP,swift.org,DIRECT // this is rule comment."
        var data: Data!
        XCTAssertNoThrow(data = try JSONSerialization.data(withJSONObject: jsonString, options: .fragmentsAllowed))
        XCTAssertNotNil(data)
        
        var standardRule: AnyRule!
        XCTAssertNoThrow(standardRule = try JSONDecoder().decode(AnyRule.self, from: data))
        XCTAssertNotNil(standardRule)
        XCTAssertEqual(standardRule.type, .geoIp)
        XCTAssertEqual(standardRule.expression, "swift.org")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertEqual(standardRule.comment, "this is rule comment.")
        
        var string: String!
        XCTAssertNoThrow(string = try JSONSerialization.jsonObject(with: JSONEncoder().encode(standardRule), options: .fragmentsAllowed) as? String)
        XCTAssertNotNil(string)
        XCTAssertEqual(string, jsonString)
    }
    
    func testParsingFinalRule() throws {
        let string = "FINAL,DIRECT"
        let standardRule = try AnyRule.init(string: string)
        XCTAssertEqual(standardRule.type, .final)
        XCTAssertEqual(standardRule.expression, "")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertEqual(standardRule.comment, "")
    }
    
    func testParsingFinalRuleWithComment() throws {
        let string = "FINAL,DIRECT // this is rule comment."
        let standardRule = try AnyRule.init(string: string)
        XCTAssertEqual(standardRule.type, .final)
        XCTAssertEqual(standardRule.expression, "")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertEqual(standardRule.comment, "this is rule comment.")
    }
    
    func testAppropriateErrorWhenParsingFinalRuleWithInvalidSchema() {
        let string = "invalidSchema,DIRECT // this is rule comment."
        
        XCTAssertThrowsError(try AnyRule.init(string: string)) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .unsupported))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
    }
    
    func testAppropriateErrorWhenParsingFinalRuleWithMissingFieldRuleString() {
        XCTAssertThrowsError(try AnyRule.init(string: "FINAL")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .missingField))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
    }
    
    func testFinalRuleCoding() throws {
        let jsonString = "FINAL,DIRECT // this is rule comment."
        var data: Data!
        XCTAssertNoThrow(data = try JSONSerialization.data(withJSONObject: jsonString, options: .fragmentsAllowed))
        XCTAssertNotNil(data)
        
        var standardRule: AnyRule!
        XCTAssertNoThrow(standardRule = try JSONDecoder().decode(AnyRule.self, from: data))
        XCTAssertNotNil(standardRule)
        XCTAssertEqual(standardRule.type, .final)
        XCTAssertEqual(standardRule.expression, "")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertEqual(standardRule.comment, "this is rule comment.")
        
        var string: String!
        XCTAssertNoThrow(string = try JSONSerialization.jsonObject(with: JSONEncoder().encode(standardRule), options: .fragmentsAllowed) as? String)
        XCTAssertNotNil(string)
        XCTAssertEqual(string, jsonString)
    }
    
    func testParsingRuleSet() throws {
        let string = "RULE-SET,http://ruleset.com,DIRECT"
        let standardRule = try AnyRule.init(string: string)
        XCTAssertEqual(standardRule.type, .ruleSet)
        XCTAssertEqual(standardRule.expression, "http://ruleset.com")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertEqual(standardRule.comment, "")
    }
    
    func testParsingRuleSetWithComment() throws {
        let string = "RULE-SET,http://ruleset.com,DIRECT // this is rule comment."
        let standardRule = try AnyRule.init(string: string)
        XCTAssertEqual(standardRule.type, .ruleSet)
        XCTAssertEqual(standardRule.expression, "http://ruleset.com")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertEqual(standardRule.comment, "this is rule comment.")
    }
    
    func testAppropriateErrorWhenParsingRuleSetWithInvalidSchema() {
        let string = "invalidSchema,http://ruleset.com,DIRECT // this is rule comment."
        
        XCTAssertThrowsError(try AnyRule.init(string: string)) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .unsupported))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
    }
    
    func testAppropriateErrorWhenParsingRuleSetWithMissingFieldRuleString() {
        XCTAssertThrowsError(try AnyRule.init(string: "RULE-SET,http://ruleset.com")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .missingField))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
    }
    
    #if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
    func testRuleSetCoding() throws {
        let text = """
DOMAIN,apple.com
DOMAIN-SUFFIX,apple.com
DOMAIN-KEYWORD,apple
"""
        
        let expectation = self.expectation(description: "RULE-SET")
        MockURLProtocol.stub(url: .init(string: "http://ruleset.com")!, response: text.data(using: .utf8)!)
        let string = "RULE-SET,http://ruleset.com,DIRECT"
        let ruleset = try AnyRule(string: string)
        ruleset.performExternalResourcesLoading { _ in
            expectation.fulfill()
        }
        waitForExpectations(timeout: 15, handler: nil)
        
        XCTAssertEqual(ruleset.expression, "http://ruleset.com")
        XCTAssertEqual(ruleset.policy, "DIRECT")
        XCTAssertEqual(ruleset.comment, "")
        XCTAssertEqual(try JSONSerialization.jsonObject(with: try JSONEncoder().encode(ruleset), options: .fragmentsAllowed) as? String, string)
    }
    #endif
}
