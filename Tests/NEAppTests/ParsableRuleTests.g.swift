//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2021 Junfeng Zhang and the Netbot project authors
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

///
/// NOTE: This file was generated by gyb
///
/// Do NOT edit this file directly as it will be regenerated automatically when needed.
///

final class ParsableRuleRepresentationTests: XCTestCase {

  func testParsingDomainKeywordRule() throws {
    let description = "DOMAIN-KEYWORD,example.com,DIRECT"
    let standardRule = try XCTUnwrap(DomainKeywordRule(description))
    XCTAssertFalse(standardRule.disabled)
    XCTAssertEqual(standardRule.expression, "example.com")
    XCTAssertEqual(standardRule.policy, "DIRECT")
    XCTAssertEqual(standardRule.description, description)
  }

  func testParsingDomainKeywordRuleThatContainComments() throws {
    let description = "DOMAIN-KEYWORD,example.com,DIRECT // comments"
    let standardRule = try XCTUnwrap(DomainKeywordRule(description))
    XCTAssertFalse(standardRule.disabled)
    XCTAssertEqual(standardRule.expression, "example.com")
    XCTAssertEqual(standardRule.policy, "DIRECT")
    XCTAssertEqual(standardRule.comment, "comments")
    XCTAssertEqual(standardRule.description, description)
  }

  func testParsingDisabledDomainKeywordRule() throws {
    let description = "# DOMAIN-KEYWORD,example.com,DIRECT"
    let standardRule = try XCTUnwrap(DomainKeywordRule(description))
    XCTAssertTrue(standardRule.disabled)
    XCTAssertEqual(standardRule.expression, "example.com")
    XCTAssertEqual(standardRule.policy, "DIRECT")
    XCTAssertEqual(standardRule.description, description)
  }

  func testParsingDomainKeywordRuleWithIncompleteDescriptionString() {
    var description = "DOMAIN-KEYWORD"
    XCTAssertNil(DomainKeywordRule(description))
    description = "DOMAIN-KEYWORD,DIRECT"
    XCTAssertNil(DomainKeywordRule(description))
  }

  func testParsingDomainKeywordRuleWithTypeMissmatchDescriptionString() {
    var description = "invalidSchema,example.com,DIRECT"
    XCTAssertNil(DomainKeywordRule(description))
    description = "DOMAIN-KEYWORD,example.com,DIRECT"
    XCTAssertNil(DomainRule(description))
    description = "DOMAIN-KEYWORD,example.com,DIRECT"
    XCTAssertNil(DomainSetRule(description))
    description = "DOMAIN-KEYWORD,example.com,DIRECT"
    XCTAssertNil(DomainSuffixRule(description))
    description = "DOMAIN-KEYWORD,example.com,DIRECT"
    XCTAssertNil(FinalRule(description))
    description = "DOMAIN-KEYWORD,example.com,DIRECT"
    XCTAssertNil(GeoIPRule(description))
    description = "DOMAIN-KEYWORD,example.com,DIRECT"
    XCTAssertNil(Ruleset(description))
  }

  func testParsingDomainRule() throws {
    let description = "DOMAIN,example.com,DIRECT"
    let standardRule = try XCTUnwrap(DomainRule(description))
    XCTAssertFalse(standardRule.disabled)
    XCTAssertEqual(standardRule.expression, "example.com")
    XCTAssertEqual(standardRule.policy, "DIRECT")
    XCTAssertEqual(standardRule.description, description)
  }

  func testParsingDomainRuleThatContainComments() throws {
    let description = "DOMAIN,example.com,DIRECT // comments"
    let standardRule = try XCTUnwrap(DomainRule(description))
    XCTAssertFalse(standardRule.disabled)
    XCTAssertEqual(standardRule.expression, "example.com")
    XCTAssertEqual(standardRule.policy, "DIRECT")
    XCTAssertEqual(standardRule.comment, "comments")
    XCTAssertEqual(standardRule.description, description)
  }

  func testParsingDisabledDomainRule() throws {
    let description = "# DOMAIN,example.com,DIRECT"
    let standardRule = try XCTUnwrap(DomainRule(description))
    XCTAssertTrue(standardRule.disabled)
    XCTAssertEqual(standardRule.expression, "example.com")
    XCTAssertEqual(standardRule.policy, "DIRECT")
    XCTAssertEqual(standardRule.description, description)
  }

  func testParsingDomainRuleWithIncompleteDescriptionString() {
    var description = "DOMAIN"
    XCTAssertNil(DomainRule(description))
    description = "DOMAIN,DIRECT"
    XCTAssertNil(DomainRule(description))
  }

  func testParsingDomainRuleWithTypeMissmatchDescriptionString() {
    var description = "invalidSchema,example.com,DIRECT"
    XCTAssertNil(DomainRule(description))
    description = "DOMAIN,example.com,DIRECT"
    XCTAssertNil(DomainKeywordRule(description))
    description = "DOMAIN,example.com,DIRECT"
    XCTAssertNil(DomainSetRule(description))
    description = "DOMAIN,example.com,DIRECT"
    XCTAssertNil(DomainSuffixRule(description))
    description = "DOMAIN,example.com,DIRECT"
    XCTAssertNil(FinalRule(description))
    description = "DOMAIN,example.com,DIRECT"
    XCTAssertNil(GeoIPRule(description))
    description = "DOMAIN,example.com,DIRECT"
    XCTAssertNil(Ruleset(description))
  }

  func testParsingDomainSetRule() throws {
    let description = "DOMAIN-SET,http://domainset.com,DIRECT"
    let standardRule = try XCTUnwrap(DomainSetRule(description))
    XCTAssertFalse(standardRule.disabled)
    XCTAssertEqual(standardRule.expression, "http://domainset.com")
    XCTAssertEqual(standardRule.policy, "DIRECT")
    XCTAssertEqual(standardRule.description, description)
  }

  func testParsingDomainSetRuleThatContainComments() throws {
    let description = "DOMAIN-SET,http://domainset.com,DIRECT // comments"
    let standardRule = try XCTUnwrap(DomainSetRule(description))
    XCTAssertFalse(standardRule.disabled)
    XCTAssertEqual(standardRule.expression, "http://domainset.com")
    XCTAssertEqual(standardRule.policy, "DIRECT")
    XCTAssertEqual(standardRule.comment, "comments")
    XCTAssertEqual(standardRule.description, description)
  }

  func testParsingDisabledDomainSetRule() throws {
    let description = "# DOMAIN-SET,http://domainset.com,DIRECT"
    let standardRule = try XCTUnwrap(DomainSetRule(description))
    XCTAssertTrue(standardRule.disabled)
    XCTAssertEqual(standardRule.expression, "http://domainset.com")
    XCTAssertEqual(standardRule.policy, "DIRECT")
    XCTAssertEqual(standardRule.description, description)
  }

  func testParsingDomainSetRuleWithIncompleteDescriptionString() {
    var description = "DOMAIN-SET"
    XCTAssertNil(DomainSetRule(description))
    description = "DOMAIN-SET,DIRECT"
    XCTAssertNil(DomainSetRule(description))
  }

  func testParsingDomainSetRuleWithTypeMissmatchDescriptionString() {
    var description = "invalidSchema,http://domainset.com,DIRECT"
    XCTAssertNil(DomainSetRule(description))
    description = "DOMAIN-SET,http://domainset.com,DIRECT"
    XCTAssertNil(DomainKeywordRule(description))
    description = "DOMAIN-SET,http://domainset.com,DIRECT"
    XCTAssertNil(DomainRule(description))
    description = "DOMAIN-SET,http://domainset.com,DIRECT"
    XCTAssertNil(DomainSuffixRule(description))
    description = "DOMAIN-SET,http://domainset.com,DIRECT"
    XCTAssertNil(FinalRule(description))
    description = "DOMAIN-SET,http://domainset.com,DIRECT"
    XCTAssertNil(GeoIPRule(description))
    description = "DOMAIN-SET,http://domainset.com,DIRECT"
    XCTAssertNil(Ruleset(description))
  }

  func testParsingDomainSuffixRule() throws {
    let description = "DOMAIN-SUFFIX,example.com,DIRECT"
    let standardRule = try XCTUnwrap(DomainSuffixRule(description))
    XCTAssertFalse(standardRule.disabled)
    XCTAssertEqual(standardRule.expression, "example.com")
    XCTAssertEqual(standardRule.policy, "DIRECT")
    XCTAssertEqual(standardRule.description, description)
  }

  func testParsingDomainSuffixRuleThatContainComments() throws {
    let description = "DOMAIN-SUFFIX,example.com,DIRECT // comments"
    let standardRule = try XCTUnwrap(DomainSuffixRule(description))
    XCTAssertFalse(standardRule.disabled)
    XCTAssertEqual(standardRule.expression, "example.com")
    XCTAssertEqual(standardRule.policy, "DIRECT")
    XCTAssertEqual(standardRule.comment, "comments")
    XCTAssertEqual(standardRule.description, description)
  }

  func testParsingDisabledDomainSuffixRule() throws {
    let description = "# DOMAIN-SUFFIX,example.com,DIRECT"
    let standardRule = try XCTUnwrap(DomainSuffixRule(description))
    XCTAssertTrue(standardRule.disabled)
    XCTAssertEqual(standardRule.expression, "example.com")
    XCTAssertEqual(standardRule.policy, "DIRECT")
    XCTAssertEqual(standardRule.description, description)
  }

  func testParsingDomainSuffixRuleWithIncompleteDescriptionString() {
    var description = "DOMAIN-SUFFIX"
    XCTAssertNil(DomainSuffixRule(description))
    description = "DOMAIN-SUFFIX,DIRECT"
    XCTAssertNil(DomainSuffixRule(description))
  }

  func testParsingDomainSuffixRuleWithTypeMissmatchDescriptionString() {
    var description = "invalidSchema,example.com,DIRECT"
    XCTAssertNil(DomainSuffixRule(description))
    description = "DOMAIN-SUFFIX,example.com,DIRECT"
    XCTAssertNil(DomainKeywordRule(description))
    description = "DOMAIN-SUFFIX,example.com,DIRECT"
    XCTAssertNil(DomainRule(description))
    description = "DOMAIN-SUFFIX,example.com,DIRECT"
    XCTAssertNil(DomainSetRule(description))
    description = "DOMAIN-SUFFIX,example.com,DIRECT"
    XCTAssertNil(FinalRule(description))
    description = "DOMAIN-SUFFIX,example.com,DIRECT"
    XCTAssertNil(GeoIPRule(description))
    description = "DOMAIN-SUFFIX,example.com,DIRECT"
    XCTAssertNil(Ruleset(description))
  }

  func testParsingFinalRule() throws {
    let description = "FINAL,DIRECT"
    let standardRule = try XCTUnwrap(FinalRule(description))
    XCTAssertFalse(standardRule.disabled)
    XCTAssertEqual(standardRule.expression, "")
    XCTAssertEqual(standardRule.policy, "DIRECT")
    XCTAssertEqual(standardRule.description, description)
  }

  func testParsingFinalRuleThatContainComments() throws {
    let description = "FINAL,DIRECT // comments"
    let standardRule = try XCTUnwrap(FinalRule(description))
    XCTAssertFalse(standardRule.disabled)
    XCTAssertEqual(standardRule.expression, "")
    XCTAssertEqual(standardRule.policy, "DIRECT")
    XCTAssertEqual(standardRule.comment, "comments")
    XCTAssertEqual(standardRule.description, description)
  }

  func testParsingDisabledFinalRule() throws {
    let description = "# FINAL,DIRECT"
    let standardRule = try XCTUnwrap(FinalRule(description))
    XCTAssertTrue(standardRule.disabled)
    XCTAssertEqual(standardRule.expression, "")
    XCTAssertEqual(standardRule.policy, "DIRECT")
    XCTAssertEqual(standardRule.description, description)
  }

  func testParsingFinalRuleWithIncompleteDescriptionString() {
    let description = "FINAL"
    XCTAssertNil(FinalRule(description))
  }

  func testParsingFinalRuleWithTypeMissmatchDescriptionString() {
    var description = "invalidSchema,DIRECT"
    XCTAssertNil(FinalRule(description))
    description = "FINAL,DIRECT"
    XCTAssertNil(DomainKeywordRule(description))
    description = "FINAL,DIRECT"
    XCTAssertNil(DomainRule(description))
    description = "FINAL,DIRECT"
    XCTAssertNil(DomainSetRule(description))
    description = "FINAL,DIRECT"
    XCTAssertNil(DomainSuffixRule(description))
    description = "FINAL,DIRECT"
    XCTAssertNil(GeoIPRule(description))
    description = "FINAL,DIRECT"
    XCTAssertNil(Ruleset(description))
  }

  func testParsingGeoIPRule() throws {
    let description = "GEOIP,example.com,DIRECT"
    let standardRule = try XCTUnwrap(GeoIPRule(description))
    XCTAssertFalse(standardRule.disabled)
    XCTAssertEqual(standardRule.expression, "example.com")
    XCTAssertEqual(standardRule.policy, "DIRECT")
    XCTAssertEqual(standardRule.description, description)
  }

  func testParsingGeoIPRuleThatContainComments() throws {
    let description = "GEOIP,example.com,DIRECT // comments"
    let standardRule = try XCTUnwrap(GeoIPRule(description))
    XCTAssertFalse(standardRule.disabled)
    XCTAssertEqual(standardRule.expression, "example.com")
    XCTAssertEqual(standardRule.policy, "DIRECT")
    XCTAssertEqual(standardRule.comment, "comments")
    XCTAssertEqual(standardRule.description, description)
  }

  func testParsingDisabledGeoIPRule() throws {
    let description = "# GEOIP,example.com,DIRECT"
    let standardRule = try XCTUnwrap(GeoIPRule(description))
    XCTAssertTrue(standardRule.disabled)
    XCTAssertEqual(standardRule.expression, "example.com")
    XCTAssertEqual(standardRule.policy, "DIRECT")
    XCTAssertEqual(standardRule.description, description)
  }

  func testParsingGeoIPRuleWithIncompleteDescriptionString() {
    var description = "GEOIP"
    XCTAssertNil(GeoIPRule(description))
    description = "GEOIP,DIRECT"
    XCTAssertNil(GeoIPRule(description))
  }

  func testParsingGeoIPRuleWithTypeMissmatchDescriptionString() {
    var description = "invalidSchema,example.com,DIRECT"
    XCTAssertNil(GeoIPRule(description))
    description = "GEOIP,example.com,DIRECT"
    XCTAssertNil(DomainKeywordRule(description))
    description = "GEOIP,example.com,DIRECT"
    XCTAssertNil(DomainRule(description))
    description = "GEOIP,example.com,DIRECT"
    XCTAssertNil(DomainSetRule(description))
    description = "GEOIP,example.com,DIRECT"
    XCTAssertNil(DomainSuffixRule(description))
    description = "GEOIP,example.com,DIRECT"
    XCTAssertNil(FinalRule(description))
    description = "GEOIP,example.com,DIRECT"
    XCTAssertNil(Ruleset(description))
  }

  func testParsingRuleset() throws {
    let description = "RULE-SET,http://ruleset.com,DIRECT"
    let standardRule = try XCTUnwrap(Ruleset(description))
    XCTAssertFalse(standardRule.disabled)
    XCTAssertEqual(standardRule.expression, "http://ruleset.com")
    XCTAssertEqual(standardRule.policy, "DIRECT")
    XCTAssertEqual(standardRule.description, description)
  }

  func testParsingRulesetThatContainComments() throws {
    let description = "RULE-SET,http://ruleset.com,DIRECT // comments"
    let standardRule = try XCTUnwrap(Ruleset(description))
    XCTAssertFalse(standardRule.disabled)
    XCTAssertEqual(standardRule.expression, "http://ruleset.com")
    XCTAssertEqual(standardRule.policy, "DIRECT")
    XCTAssertEqual(standardRule.comment, "comments")
    XCTAssertEqual(standardRule.description, description)
  }

  func testParsingDisabledRuleset() throws {
    let description = "# RULE-SET,http://ruleset.com,DIRECT"
    let standardRule = try XCTUnwrap(Ruleset(description))
    XCTAssertTrue(standardRule.disabled)
    XCTAssertEqual(standardRule.expression, "http://ruleset.com")
    XCTAssertEqual(standardRule.policy, "DIRECT")
    XCTAssertEqual(standardRule.description, description)
  }

  func testParsingRulesetWithIncompleteDescriptionString() {
    var description = "RULE-SET"
    XCTAssertNil(Ruleset(description))
    description = "RULE-SET,DIRECT"
    XCTAssertNil(Ruleset(description))
  }

  func testParsingRulesetWithTypeMissmatchDescriptionString() {
    var description = "invalidSchema,http://ruleset.com,DIRECT"
    XCTAssertNil(Ruleset(description))
    description = "RULE-SET,http://ruleset.com,DIRECT"
    XCTAssertNil(DomainKeywordRule(description))
    description = "RULE-SET,http://ruleset.com,DIRECT"
    XCTAssertNil(DomainRule(description))
    description = "RULE-SET,http://ruleset.com,DIRECT"
    XCTAssertNil(DomainSetRule(description))
    description = "RULE-SET,http://ruleset.com,DIRECT"
    XCTAssertNil(DomainSuffixRule(description))
    description = "RULE-SET,http://ruleset.com,DIRECT"
    XCTAssertNil(FinalRule(description))
    description = "RULE-SET,http://ruleset.com,DIRECT"
    XCTAssertNil(GeoIPRule(description))
  }

  func testDomainKeywordRuleMatchEvaluating() {
    let rule = DomainKeywordRule("DOMAIN-KEYWORD,example,DIRECT")!
    let testVectors = [
      ("example.com", true),
      ("www.example.com", true),
      ("example", true),
      ("pexample.com", true),
      ("example1.com", true),
    ]
    testVectors.forEach { pattern, expected in
      XCTAssertEqual(rule.match(pattern), expected)
    }
  }

  func testDomainRuleMatchEvaluating() {
    let rule = DomainRule("DOMAIN,example.com,DIRECT")!
    let testVectors = [
      ("example.com", true),
      ("www.example.com", false),
      ("example", false),
    ]
    testVectors.forEach { pattern, expected in
      XCTAssertEqual(rule.match(pattern), expected)
    }
  }

  func testDomainSuffixRuleMatchEvaluating() {
    let rule = DomainSuffixRule("DOMAIN-SUFFIX,example.com,DIRECT")!
    let testVectors = [
      ("example.com", true),
      ("www.example.com", true),
      ("example", false),
    ]
    testVectors.forEach { pattern, expected in
      XCTAssertEqual(rule.match(pattern), expected)
    }
  }
}