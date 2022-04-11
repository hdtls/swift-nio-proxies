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
    
    func assertRuleCodingSuccess<R>(_ type: R.Type, expect: String) where R: Codable {
        var data: Data!
        
        XCTAssertNoThrow(data = try JSONSerialization.data(withJSONObject: expect, options: .fragmentsAllowed))
        XCTAssertNotNil(data)
        
        var standardRule: R!
        XCTAssertNoThrow(standardRule = try JSONDecoder().decode(R.self, from: data))
        XCTAssertNotNil(standardRule)
        
        var stringLiteral: String!
        XCTAssertNoThrow(stringLiteral = try JSONSerialization.jsonObject(with: JSONEncoder().encode(standardRule), options: .fragmentsAllowed) as? String)
        XCTAssertNotNil(stringLiteral)
        
        XCTAssertEqual(stringLiteral, expect)
    }
    
    func testParsingDomainRule() throws {
        let stringLiteral = "DOMAIN,swift.org,DIRECT"
        let standardRule = try DomainRule.init(stringLiteral: stringLiteral)
        XCTAssertEqual(standardRule.pattern, "swift.org")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertNil(standardRule.comment)
    }
    
    func testParsingDomainRuleWithComment() throws {
        let stringLiteral = "DOMAIN,swift.org,DIRECT // This is rule comment."
        let standardRule = try DomainRule.init(stringLiteral: stringLiteral)
        XCTAssertEqual(standardRule.pattern, "swift.org")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertEqual(standardRule.comment, "This is rule comment.")
    }
    
    func testAppropriateErrorWhenParsingDomainRuleWithInvalidSchema() {
        let stringLiteral = "invalidSchema,swift.org,DIRECT // This is rule comment."

        XCTAssertThrowsError(try DomainRule.init(stringLiteral: stringLiteral)) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .unsupported))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
    }
    
    func testAppropriateErrorWhenParsingDomainRuleWithUnmatchedSchema() {
        
        XCTAssertThrowsError(try DomainRule.init(stringLiteral: "DOMAIN-SUFFIX,swift.org,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(DomainRule.self, butCanBeParsedAs: DomainSuffixRule.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
        
        XCTAssertThrowsError(try DomainRule.init(stringLiteral: "DOMAIN-KEYWORD,swift.org,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(DomainRule.self, butCanBeParsedAs: DomainKeywordRule.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
        
        XCTAssertThrowsError(try DomainRule.init(stringLiteral: "DOMAIN-SET,swift.org,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(DomainRule.self, butCanBeParsedAs: DomainSet.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
        
        XCTAssertThrowsError(try DomainRule.init(stringLiteral: "GEOIP,swift.org,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(DomainRule.self, butCanBeParsedAs: GeoIPRule.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
        
        XCTAssertThrowsError(try DomainRule.init(stringLiteral: "FINAL,swift.org,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(DomainRule.self, butCanBeParsedAs: FinalRule.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
        
        XCTAssertThrowsError(try DomainRule.init(stringLiteral: "RULE-SET,swift.org,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(DomainRule.self, butCanBeParsedAs: RuleSet.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
    }
    
    func testAppropriateErrorWhenParsingDomainRuleWithMissingFieldRuleString() {
        XCTAssertThrowsError(try DomainRule.init(stringLiteral: "DOMAIN,swift.org")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .missingField))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
    }
    
    func testDomainRuleCoding() throws {
        assertRuleCodingSuccess(DomainRule.self, expect: "DOMAIN,swift.org,DIRECT")
        assertRuleCodingSuccess(DomainRule.self, expect: "DOMAIN,swift.org,DIRECT // This is rule comment.")
    }
    
    func testParsingDomainSuffixRule() throws {
        let stringLiteral = "DOMAIN-SUFFIX,swift.org,DIRECT"
        let standardRule = try DomainSuffixRule.init(stringLiteral: stringLiteral)
        XCTAssertEqual(standardRule.pattern, "swift.org")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertNil(standardRule.comment)
    }
    
    func testParsingDomainSuffixRuleWithComment() throws {
        let stringLiteral = "DOMAIN-SUFFIX,swift.org,DIRECT // This is rule comment."
        let standardRule = try DomainSuffixRule.init(stringLiteral: stringLiteral)
        XCTAssertEqual(standardRule.pattern, "swift.org")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertEqual(standardRule.comment, "This is rule comment.")
    }
    
    func testAppropriateErrorWhenParsingDomainSuffixRuleWithInvalidSchema() {
        let stringLiteral = "invalidSchema,swift.org,DIRECT // This is rule comment."

        XCTAssertThrowsError(try DomainSuffixRule.init(stringLiteral: stringLiteral)) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .unsupported))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
    }
    
    func testAppropriateErrorWhenParsingDomainSuffixRuleWithUnmatchedSchema() {
        
        XCTAssertThrowsError(try DomainSuffixRule.init(stringLiteral: "DOMAIN,swift.org,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(DomainSuffixRule.self, butCanBeParsedAs: DomainRule.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
        
        XCTAssertThrowsError(try DomainSuffixRule.init(stringLiteral: "DOMAIN-KEYWORD,swift.org,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(DomainSuffixRule.self, butCanBeParsedAs: DomainKeywordRule.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
        
        XCTAssertThrowsError(try DomainSuffixRule.init(stringLiteral: "DOMAIN-SET,swift.org,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(DomainSuffixRule.self, butCanBeParsedAs: DomainSet.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
        
        XCTAssertThrowsError(try DomainSuffixRule.init(stringLiteral: "GEOIP,swift.org,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(DomainSuffixRule.self, butCanBeParsedAs: GeoIPRule.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
        
        XCTAssertThrowsError(try DomainSuffixRule.init(stringLiteral: "FINAL,swift.org,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(DomainSuffixRule.self, butCanBeParsedAs: FinalRule.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
        
        XCTAssertThrowsError(try DomainSuffixRule.init(stringLiteral: "RULE-SET,swift.org,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(DomainSuffixRule.self, butCanBeParsedAs: RuleSet.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
    }
    
    func testAppropriateErrorWhenParsingDomainSuffixRuleWithMissingFieldRuleString() {
        XCTAssertThrowsError(try DomainSuffixRule.init(stringLiteral: "DOMAIN-SUFFIX,swift.org")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .missingField))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
    }
    
    func testDomainSuffixRuleCoding() throws {
        assertRuleCodingSuccess(DomainSuffixRule.self, expect: "DOMAIN-SUFFIX,swift.org,DIRECT")
        assertRuleCodingSuccess(DomainSuffixRule.self, expect: "DOMAIN-SUFFIX,swift.org,DIRECT // This is rule comment.")
    }
    
    func testParsingDomainKeywordRule() throws {
        let stringLiteral = "DOMAIN-KEYWORD,swift.org,DIRECT"
        let standardRule = try DomainKeywordRule.init(stringLiteral: stringLiteral)
        XCTAssertEqual(standardRule.pattern, "swift.org")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertNil(standardRule.comment)
    }
    
    func testParsingDomainKeywordRuleWithComment() throws {
        let stringLiteral = "DOMAIN-KEYWORD,swift.org,DIRECT // This is rule comment."
        let standardRule = try DomainKeywordRule.init(stringLiteral: stringLiteral)
        XCTAssertEqual(standardRule.pattern, "swift.org")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertEqual(standardRule.comment, "This is rule comment.")
    }
    
    func testAppropriateErrorWhenParsingDomainKeywordRuleWithInvalidSchema() {
        let stringLiteral = "invalidSchema,swift.org,DIRECT // This is rule comment."

        XCTAssertThrowsError(try DomainKeywordRule.init(stringLiteral: stringLiteral)) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .unsupported))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
    }
    
    func testAppropriateErrorWhenParsingDomainKeywordRuleWithUnmatchedSchema() {
        
        XCTAssertThrowsError(try DomainKeywordRule.init(stringLiteral: "DOMAIN,swift.org,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(DomainKeywordRule.self, butCanBeParsedAs: DomainRule.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
        
        XCTAssertThrowsError(try DomainKeywordRule.init(stringLiteral: "DOMAIN-SUFFIX,swift.org,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(DomainKeywordRule.self, butCanBeParsedAs: DomainSuffixRule.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
        
        XCTAssertThrowsError(try DomainKeywordRule.init(stringLiteral: "DOMAIN-SET,swift.org,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(DomainKeywordRule.self, butCanBeParsedAs: DomainSet.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
        
        XCTAssertThrowsError(try DomainKeywordRule.init(stringLiteral: "GEOIP,swift.org,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(DomainKeywordRule.self, butCanBeParsedAs: GeoIPRule.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
        
        XCTAssertThrowsError(try DomainKeywordRule.init(stringLiteral: "FINAL,swift.org,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(DomainKeywordRule.self, butCanBeParsedAs: FinalRule.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
        
        XCTAssertThrowsError(try DomainKeywordRule.init(stringLiteral: "RULE-SET,swift.org,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(DomainKeywordRule.self, butCanBeParsedAs: RuleSet.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
    }
    
    func testAppropriateErrorWhenParsingDomainKeywordRuleWithMissingFieldRuleString() {
        XCTAssertThrowsError(try DomainKeywordRule.init(stringLiteral: "DOMAIN-KEYWORD,swift.org")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .missingField))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
    }
    
    func testDomainKeywordRuleCoding() throws {
        assertRuleCodingSuccess(DomainKeywordRule.self, expect: "DOMAIN-KEYWORD,swift.org,DIRECT")
        assertRuleCodingSuccess(DomainKeywordRule.self, expect: "DOMAIN-KEYWORD,swift.org,DIRECT // This is rule comment.")
    }
    
    func testParsingDomainSet() throws {
        let stringLiteral = "DOMAIN-SET,http://domainset.com,DIRECT"
        let standardRule = try DomainSet.init(stringLiteral: stringLiteral)
        XCTAssertEqual(standardRule.pattern, "http://domainset.com")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertNil(standardRule.comment)
    }
    
    func testParsingDomainSetWithComment() throws {
        let stringLiteral = "DOMAIN-SET,http://domainset.com,DIRECT // This is rule comment."
        let standardRule = try DomainSet.init(stringLiteral: stringLiteral)
        XCTAssertEqual(standardRule.pattern, "http://domainset.com")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertEqual(standardRule.comment, "This is rule comment.")
    }
    
    func testAppropriateErrorWhenParsingDomainSetWithInvalidSchema() {
        let stringLiteral = "invalidSchema,http://domainset.com,DIRECT // This is rule comment."

        XCTAssertThrowsError(try DomainSet.init(stringLiteral: stringLiteral)) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .unsupported))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
    }
    
    func testAppropriateErrorWhenParsingDomainSetWithUnmatchedSchema() {
        
        XCTAssertThrowsError(try DomainSet.init(stringLiteral: "DOMAIN,http://domainset.com,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(DomainSet.self, butCanBeParsedAs: DomainRule.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
        
        XCTAssertThrowsError(try DomainSet.init(stringLiteral: "DOMAIN-SUFFIX,http://domainset.com,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(DomainSet.self, butCanBeParsedAs: DomainSuffixRule.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
        
        XCTAssertThrowsError(try DomainSet.init(stringLiteral: "DOMAIN-KEYWORD,http://domainset.com,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(DomainSet.self, butCanBeParsedAs: DomainKeywordRule.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
        
        XCTAssertThrowsError(try DomainSet.init(stringLiteral: "GEOIP,http://domainset.com,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(DomainSet.self, butCanBeParsedAs: GeoIPRule.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
        
        XCTAssertThrowsError(try DomainSet.init(stringLiteral: "FINAL,http://domainset.com,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(DomainSet.self, butCanBeParsedAs: FinalRule.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
        
        XCTAssertThrowsError(try DomainSet.init(stringLiteral: "RULE-SET,http://domainset.com,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(DomainSet.self, butCanBeParsedAs: RuleSet.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
    }
    
    func testAppropriateErrorWhenParsingDomainSetWithMissingFieldRuleString() {
        XCTAssertThrowsError(try DomainSet.init(stringLiteral: "DOMAIN-SET,http://domainset.com")) { error in
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
        let stringLiteral = "DOMAIN-SET,http://domainset.com,DIRECT"
        let domainset = try DomainSet(stringLiteral: stringLiteral)
        domainset.performLoadingExternalResources { _ in
            expectation.fulfill()
        }
        waitForExpectations(timeout: 5, handler: nil)
        
        XCTAssertEqual(domainset.pattern, "http://domainset.com")
        XCTAssertEqual(domainset.policy, "DIRECT")
        XCTAssertNil(domainset.comment)
        XCTAssertEqual(domainset.standardRules.count, try text.components(separatedBy: "\n").map { try AnyRule(stringLiteral: "DOMAIN-SUFFIX,\($0),DIRECT") }.count)
        XCTAssertEqual(try JSONSerialization.jsonObject(with: try JSONEncoder().encode(domainset), options: .fragmentsAllowed) as? String, stringLiteral)
    }
    #endif
    
    func testParsingGeoIPRule() throws {
        let stringLiteral = "GEOIP,swift.org,DIRECT"
        let standardRule = try GeoIPRule.init(stringLiteral: stringLiteral)
        XCTAssertEqual(standardRule.pattern, "swift.org")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertNil(standardRule.comment)
    }
    
    func testParsingGeoIPRuleWithComment() throws {
        let stringLiteral = "GEOIP,swift.org,DIRECT // This is rule comment."
        let standardRule = try GeoIPRule.init(stringLiteral: stringLiteral)
        XCTAssertEqual(standardRule.pattern, "swift.org")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertEqual(standardRule.comment, "This is rule comment.")
    }
    
    func testAppropriateErrorWhenParsingGeoIPRuleWithInvalidSchema() {
        let stringLiteral = "invalidSchema,swift.org,DIRECT // This is rule comment."

        XCTAssertThrowsError(try GeoIPRule.init(stringLiteral: stringLiteral)) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .unsupported))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
    }
    
    func testAppropriateErrorWhenParsingGeoIPRuleWithUnmatchedSchema() {
        
        XCTAssertThrowsError(try GeoIPRule.init(stringLiteral: "DOMAIN,swift.org,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(GeoIPRule.self, butCanBeParsedAs: DomainRule.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
        
        XCTAssertThrowsError(try GeoIPRule.init(stringLiteral: "DOMAIN-SUFFIX,swift.org,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(GeoIPRule.self, butCanBeParsedAs: DomainSuffixRule.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
        
        XCTAssertThrowsError(try GeoIPRule.init(stringLiteral: "DOMAIN-KEYWORD,swift.org,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(GeoIPRule.self, butCanBeParsedAs: DomainKeywordRule.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
        
        XCTAssertThrowsError(try GeoIPRule.init(stringLiteral: "DOMAIN-SET,swift.org,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(GeoIPRule.self, butCanBeParsedAs: DomainSet.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
        
        XCTAssertThrowsError(try GeoIPRule.init(stringLiteral: "FINAL,swift.org,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(GeoIPRule.self, butCanBeParsedAs: FinalRule.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
        
        XCTAssertThrowsError(try GeoIPRule.init(stringLiteral: "RULE-SET,swift.org,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(GeoIPRule.self, butCanBeParsedAs: RuleSet.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
    }
    
    func testAppropriateErrorWhenParsingGeoIPRuleWithMissingFieldRuleString() {
        XCTAssertThrowsError(try GeoIPRule.init(stringLiteral: "GEOIP,swift.org")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .missingField))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
    }
    
    func testGeoIPRuleCoding() throws {
        assertRuleCodingSuccess(GeoIPRule.self, expect: "GEOIP,swift.org,DIRECT")
        assertRuleCodingSuccess(GeoIPRule.self, expect: "GEOIP,swift.org,DIRECT // This is rule comment.")
    }
    
    func testParsingFinalRule() throws {
        let stringLiteral = "FINAL,swift.org,DIRECT"
        let standardRule = try FinalRule.init(stringLiteral: stringLiteral)
        XCTAssertEqual(standardRule.pattern, "swift.org")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertNil(standardRule.comment)
    }
    
    func testParsingFinalRuleWithComment() throws {
        let stringLiteral = "FINAL,swift.org,DIRECT // This is rule comment."
        let standardRule = try FinalRule.init(stringLiteral: stringLiteral)
        XCTAssertEqual(standardRule.pattern, "swift.org")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertEqual(standardRule.comment, "This is rule comment.")
    }
    
    func testAppropriateErrorWhenParsingFinalRuleWithInvalidSchema() {
        let stringLiteral = "invalidSchema,swift.org,DIRECT // This is rule comment."

        XCTAssertThrowsError(try FinalRule.init(stringLiteral: stringLiteral)) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .unsupported))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
    }
    
    func testAppropriateErrorWhenParsingFinalRuleWithUnmatchedSchema() {
        
        XCTAssertThrowsError(try FinalRule.init(stringLiteral: "DOMAIN,swift.org,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(FinalRule.self, butCanBeParsedAs: DomainRule.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
        
        XCTAssertThrowsError(try FinalRule.init(stringLiteral: "DOMAIN-SUFFIX,swift.org,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(FinalRule.self, butCanBeParsedAs: DomainSuffixRule.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
        
        XCTAssertThrowsError(try FinalRule.init(stringLiteral: "DOMAIN-KEYWORD,swift.org,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(FinalRule.self, butCanBeParsedAs: DomainKeywordRule.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
        
        XCTAssertThrowsError(try FinalRule.init(stringLiteral: "DOMAIN-SET,swift.org,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(FinalRule.self, butCanBeParsedAs: DomainSet.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
        
        XCTAssertThrowsError(try FinalRule.init(stringLiteral: "GEOIP,swift.org,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(FinalRule.self, butCanBeParsedAs: GeoIPRule.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
        
        XCTAssertThrowsError(try FinalRule.init(stringLiteral: "RULE-SET,swift.org,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(FinalRule.self, butCanBeParsedAs: RuleSet.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
    }
    
    func testAppropriateErrorWhenParsingFinalRuleWithMissingFieldRuleString() {
        XCTAssertThrowsError(try FinalRule.init(stringLiteral: "FINAL,swift.org")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .missingField))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
    }
    
    func testFinalRuleCoding() throws {
        assertRuleCodingSuccess(FinalRule.self, expect: "FINAL,swift.org,DIRECT")
        assertRuleCodingSuccess(FinalRule.self, expect: "FINAL,swift.org,DIRECT // This is rule comment.")
    }
    
    func testParsingRuleSet() throws {
        let stringLiteral = "RULE-SET,http://ruleset.com,DIRECT"
        let standardRule = try RuleSet.init(stringLiteral: stringLiteral)
        XCTAssertEqual(standardRule.pattern, "http://ruleset.com")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertNil(standardRule.comment)
    }
    
    func testParsingRuleSetWithComment() throws {
        let stringLiteral = "RULE-SET,http://ruleset.com,DIRECT // This is rule comment."
        let standardRule = try RuleSet.init(stringLiteral: stringLiteral)
        XCTAssertEqual(standardRule.pattern, "http://ruleset.com")
        XCTAssertEqual(standardRule.policy, "DIRECT")
        XCTAssertEqual(standardRule.comment, "This is rule comment.")
    }
    
    func testAppropriateErrorWhenParsingRuleSetWithInvalidSchema() {
        let stringLiteral = "invalidSchema,http://ruleset.com,DIRECT // This is rule comment."

        XCTAssertThrowsError(try RuleSet.init(stringLiteral: stringLiteral)) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .unsupported))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
    }
    
    func testAppropriateErrorWhenParsingRuleSetWithUnmatchedSchema() {
        
        XCTAssertThrowsError(try RuleSet.init(stringLiteral: "DOMAIN,http://ruleset.com,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(RuleSet.self, butCanBeParsedAs: DomainRule.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
        
        XCTAssertThrowsError(try RuleSet.init(stringLiteral: "DOMAIN-SUFFIX,http://ruleset.com,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(RuleSet.self, butCanBeParsedAs: DomainSuffixRule.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
        
        XCTAssertThrowsError(try RuleSet.init(stringLiteral: "DOMAIN-KEYWORD,http://ruleset.com,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(RuleSet.self, butCanBeParsedAs: DomainKeywordRule.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
        
        XCTAssertThrowsError(try RuleSet.init(stringLiteral: "DOMAIN-SET,http://ruleset.com,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(RuleSet.self, butCanBeParsedAs: DomainSet.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
        
        XCTAssertThrowsError(try RuleSet.init(stringLiteral: "GEOIP,http://ruleset.com,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(RuleSet.self, butCanBeParsedAs: GeoIPRule.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
        
        XCTAssertThrowsError(try RuleSet.init(stringLiteral: "FINAL,http://ruleset.com,DIRECT")) { error in
            XCTAssertTrue(error is ConfigurationSerializationError)
            let actualErrorString = String(describing: error as! ConfigurationSerializationError)
            let expectedErrorString = String(describing: ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(RuleSet.self, butCanBeParsedAs: FinalRule.self)))
            XCTAssertEqual(actualErrorString, expectedErrorString)
        }
    }
    
    func testAppropriateErrorWhenParsingRuleSetWithMissingFieldRuleString() {
        XCTAssertThrowsError(try RuleSet.init(stringLiteral: "RULE-SET,http://ruleset.com")) { error in
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
        let stringLiteral = "RULE-SET,http://ruleset.com,DIRECT"
        let ruleset = try RuleSet(stringLiteral: stringLiteral)
        ruleset.performLoadingExternalResources { _ in
            expectation.fulfill()
        }
        waitForExpectations(timeout: 30, handler: nil)
        
        XCTAssertEqual(ruleset.pattern, "http://ruleset.com")
        XCTAssertEqual(ruleset.policy, "DIRECT")
        XCTAssertNil(ruleset.comment)
        XCTAssertEqual(ruleset.standardRules.count, try text.components(separatedBy: "\n").map { try AnyRule(stringLiteral: $0 + ",DIRECT") }.count)
        XCTAssertEqual(try JSONSerialization.jsonObject(with: try JSONEncoder().encode(ruleset), options: .fragmentsAllowed) as? String, stringLiteral)
    }
    #endif
    
    func testParsingAnyRule() throws {
        func assertUnderliyingRule<T: Rule & Equatable>(_ stringLiteral: String, _ type: T.Type) throws {
            let expected = try AnyRule.init(stringLiteral: stringLiteral)
            XCTAssertTrue(expected.base is T)
            XCTAssertEqual(expected.base as! T, try T.init(stringLiteral: stringLiteral))
        }
        
        try assertUnderliyingRule("DOMAIN,apple.com,DIRECT", DomainRule.self)
        try assertUnderliyingRule("DOMAIN-SUFFIX,apple.com,DIRECT", DomainSuffixRule.self)
        try assertUnderliyingRule("DOMAIN-KEYWORD,apple.com,DIRECT", DomainKeywordRule.self)
        try assertUnderliyingRule("FINAL,dns-failed,DIRECT", FinalRule.self)
        try assertUnderliyingRule("GEOIP,CN,DIRECT", GeoIPRule.self)
        
#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
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
        
        XCTAssertTrue(actual.base is RuleSet)
        XCTAssertEqual(actual.base as! RuleSet, expected)
        
        XCTAssertTrue(actual1.base is DomainSet)
        XCTAssertEqual(actual1.base as! DomainSet, expected1)
#endif
    }
}
