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

final class RuleFormatStyleTests: XCTestCase {

  func testInitialFieldsValue() {
    var formatStyle = RuleFormatStyle<DomainRule>()
    XCTAssertEqual(formatStyle.fields, Set())
    XCTAssertNil(formatStyle.style)

    formatStyle = RuleFormatStyle<DomainRule>(style: .complete)
    XCTAssertEqual(formatStyle.fields, Set())
    XCTAssertEqual(formatStyle.style, .complete)

    formatStyle = RuleFormatStyle<DomainRule>(style: .omitted)
    XCTAssertEqual(formatStyle.fields, Set())
    XCTAssertEqual(formatStyle.style, .omitted)
  }

  func testModifyFormatStyleFields() {
    var formatStyle = RuleFormatStyle<DomainRule>()
    XCTAssertEqual(formatStyle.fields, Set())

    formatStyle = formatStyle.flag()
    XCTAssertEqual(formatStyle.fields, Set([.flag]))

    formatStyle = formatStyle.symbols()
    XCTAssertEqual(formatStyle.fields, Set([.flag, .symbols]))

    formatStyle = formatStyle.expression()
    XCTAssertEqual(formatStyle.fields, Set([.flag, .symbols, .expression]))

    formatStyle = formatStyle.policy()
    XCTAssertEqual(formatStyle.fields, Set([.flag, .symbols, .expression, .policy]))

    formatStyle = formatStyle.comment()
    XCTAssertEqual(formatStyle.fields, Set([.flag, .symbols, .expression, .policy, .comment]))

    formatStyle = RuleFormatStyle<DomainRule>().omitted()
    XCTAssertEqual(formatStyle.fields, Set([.flag, .symbols, .policy, .comment]))

    formatStyle = RuleFormatStyle<DomainRule>().complete()
    XCTAssertEqual(formatStyle.fields, Set([.flag, .symbols, .expression, .policy, .comment]))
  }

  func testFormatRuleWithCompleteOrNilRuleStyle() {
    var rule = DomainRule("# DOMAIN,www.example.com,DIRECT // comments")!

    var formatStyle = RuleFormatStyle<DomainRule>(style: .complete)
    var formatOutput = formatStyle.format(rule)
    XCTAssertEqual(formatOutput, "")

    formatStyle = formatStyle.flag()
    formatOutput = formatStyle.format(rule)
    XCTAssertEqual(formatOutput, "# ")

    formatStyle = RuleFormatStyle<DomainRule>()
    formatStyle = formatStyle.symbols()
    formatOutput = formatStyle.format(rule)
    XCTAssertEqual(formatOutput, "DOMAIN")

    formatStyle = RuleFormatStyle<DomainRule>()
    formatStyle = formatStyle.expression()
    formatOutput = formatStyle.format(rule)
    XCTAssertEqual(formatOutput, "www.example.com")

    formatStyle = RuleFormatStyle<DomainRule>()
    formatStyle = formatStyle.policy()
    formatOutput = formatStyle.format(rule)
    XCTAssertEqual(formatOutput, "DIRECT")

    formatStyle = RuleFormatStyle<DomainRule>()
    formatStyle = formatStyle.comment()
    formatOutput = formatStyle.format(rule)
    XCTAssertEqual(formatOutput, " // comments")

    formatStyle = RuleFormatStyle<DomainRule>()
    formatStyle = formatStyle.flag().expression()
    formatOutput = formatStyle.format(rule)
    XCTAssertEqual(formatOutput, "# www.example.com")

    formatStyle = RuleFormatStyle<DomainRule>()
    formatStyle = formatStyle.symbols().expression()
    formatOutput = formatStyle.format(rule)
    XCTAssertEqual(formatOutput, "DOMAIN,www.example.com")

    formatStyle = RuleFormatStyle<DomainRule>()
    formatStyle = formatStyle.omitted()
    formatOutput = formatStyle.format(rule)
    XCTAssertEqual(formatOutput, "# DOMAIN,DIRECT // comments")

    formatStyle = RuleFormatStyle<DomainRule>()
    formatStyle = formatStyle.complete()
    formatOutput = formatStyle.format(rule)
    XCTAssertEqual(formatOutput, "# DOMAIN,www.example.com,DIRECT // comments")

    rule = DomainRule("# DOMAIN,www.example.com,DIRECT")!
    formatOutput = formatStyle.format(rule)
    XCTAssertEqual(formatOutput, "# DOMAIN,www.example.com,DIRECT")
  }

  func testFormatRuleWithOmittedRuleStyle() {
    let rule = FinalRule("# FINAL,DIRECT // comments")!

    var formatStyle = RuleFormatStyle<FinalRule>(style: .omitted)
    var formatOutput = formatStyle.format(rule)
    XCTAssertEqual(formatOutput, "")

    formatStyle = formatStyle.flag()
    formatOutput = formatStyle.format(rule)
    XCTAssertEqual(formatOutput, "# ")

    formatStyle = RuleFormatStyle<FinalRule>(style: .omitted)
    formatStyle = formatStyle.symbols()
    formatOutput = formatStyle.format(rule)
    XCTAssertEqual(formatOutput, "FINAL")

    formatStyle = RuleFormatStyle<FinalRule>(style: .omitted)
    formatStyle = formatStyle.expression()
    formatOutput = formatStyle.format(rule)
    XCTAssertEqual(formatOutput, "")

    formatStyle = RuleFormatStyle<FinalRule>(style: .omitted)
    formatStyle = formatStyle.policy()
    formatOutput = formatStyle.format(rule)
    XCTAssertEqual(formatOutput, "DIRECT")

    formatStyle = RuleFormatStyle<FinalRule>(style: .omitted)
    formatStyle = formatStyle.comment()
    formatOutput = formatStyle.format(rule)
    XCTAssertEqual(formatOutput, " // comments")

    formatStyle = RuleFormatStyle<FinalRule>(style: .omitted)
    formatStyle = formatStyle.flag().expression()
    formatOutput = formatStyle.format(rule)
    XCTAssertEqual(formatOutput, "# ")

    formatStyle = RuleFormatStyle<FinalRule>(style: .omitted)
    formatStyle = formatStyle.symbols().expression()
    formatOutput = formatStyle.format(rule)
    XCTAssertEqual(formatOutput, "FINAL")

    formatStyle = RuleFormatStyle<FinalRule>(style: .omitted)
    formatStyle = formatStyle.omitted()
    formatOutput = formatStyle.format(rule)
    XCTAssertEqual(formatOutput, "# FINAL,DIRECT // comments")

    formatStyle = RuleFormatStyle<FinalRule>(style: .omitted)
    formatStyle = formatStyle.complete()
    formatOutput = formatStyle.format(rule)
    XCTAssertEqual(formatOutput, "# FINAL,DIRECT // comments")
  }

  func testParseRuleWithCompleteOrNilRuleStyle() throws {
    let parseInput = "# DOMAIN,www.example.com,DIRECT // comments"

    var formatStyle = RuleFormatStyle<DomainRule>()
    var parseOutput = try formatStyle.parse(parseInput)
    var expected = DomainRule()
    XCTAssertEqual(parseOutput, expected)

    formatStyle = RuleFormatStyle<DomainRule>().flag()
    parseOutput = try formatStyle.parse(parseInput)
    expected = DomainRule()
    expected.disabled = true
    XCTAssertEqual(parseOutput, expected)

    formatStyle = RuleFormatStyle<DomainRule>().symbols()
    parseOutput = try formatStyle.parse(parseInput)
    XCTAssertEqual(parseOutput, DomainRule())

    formatStyle = RuleFormatStyle<DomainRule>().expression()
    parseOutput = try formatStyle.parse(parseInput)
    expected = DomainRule()
    expected.expression = "www.example.com"
    XCTAssertEqual(parseOutput, expected)

    formatStyle = RuleFormatStyle<DomainRule>().policy()
    parseOutput = try formatStyle.parse(parseInput)
    expected = DomainRule()
    expected.policy = "DIRECT"
    XCTAssertEqual(parseOutput, expected)

    formatStyle = RuleFormatStyle<DomainRule>().comment()
    parseOutput = try formatStyle.parse(parseInput)
    expected = DomainRule()
    expected.comment = "comments"
    XCTAssertEqual(parseOutput, expected)

    formatStyle = RuleFormatStyle<DomainRule>().flag().complete()
    parseOutput = try formatStyle.parse(parseInput)
    expected = DomainRule()
    expected.disabled = true
    expected.expression = "www.example.com"
    expected.policy = "DIRECT"
    expected.comment = "comments"
    XCTAssertEqual(parseOutput, expected)
  }

  func testParseRuleWithOmittedRuleStyle() throws {
    let parseInput = "# FINAL,DIRECT // comments"

    var formatStyle = RuleFormatStyle<FinalRule>(style: .omitted)
    var parseOutput = try formatStyle.parse(parseInput)
    var expected = FinalRule()
    XCTAssertEqual(parseOutput, expected)

    formatStyle = RuleFormatStyle<FinalRule>(style: .omitted).flag()
    parseOutput = try formatStyle.parse(parseInput)
    expected = FinalRule()
    expected.disabled = true
    XCTAssertEqual(parseOutput, expected)

    formatStyle = RuleFormatStyle<FinalRule>(style: .omitted).symbols()
    parseOutput = try formatStyle.parse(parseInput)
    XCTAssertEqual(parseOutput, FinalRule())

    formatStyle = RuleFormatStyle<FinalRule>(style: .omitted).expression()
    parseOutput = try formatStyle.parse(parseInput)
    expected = FinalRule()
    XCTAssertEqual(parseOutput, expected)

    formatStyle = RuleFormatStyle<FinalRule>(style: .omitted).policy()
    parseOutput = try formatStyle.parse(parseInput)
    expected = FinalRule()
    expected.policy = "DIRECT"
    XCTAssertEqual(parseOutput, expected)

    formatStyle = RuleFormatStyle<FinalRule>(style: .omitted).comment()
    parseOutput = try formatStyle.parse(parseInput)
    expected = FinalRule()
    expected.comment = "comments"
    XCTAssertEqual(parseOutput, expected)

    formatStyle = RuleFormatStyle<FinalRule>(style: .omitted).flag().complete()
    parseOutput = try formatStyle.parse(parseInput)
    expected = FinalRule()
    expected.disabled = true
    expected.policy = "DIRECT"
    expected.comment = "comments"
    XCTAssertEqual(parseOutput, expected)
  }

  func testAppropriateErrorWhenParsingWithInvalidInput() throws {
    var parseInput = "# DOMAIN-SUFFIX"

    var formatStyle = RuleFormatStyle<DomainRule>()
    XCTAssertThrowsError(try formatStyle.parse(parseInput)) {
      guard case .dataCorrupted = $0 as? DecodingError else {
        XCTFail()
        return
      }
    }

    formatStyle = formatStyle.flag().symbols().expression()
    XCTAssertThrowsError(try formatStyle.parse(parseInput)) {
      guard case .valueNotFound = $0 as? DecodingError else {
        XCTFail()
        return
      }
    }

    formatStyle = RuleFormatStyle<DomainRule>(style: .omitted)
    XCTAssertThrowsError(try formatStyle.parse(parseInput)) {
      guard case .dataCorrupted = $0 as? DecodingError else {
        XCTFail()
        return
      }
    }

    formatStyle = formatStyle.flag().symbols().policy()
    XCTAssertThrowsError(try formatStyle.parse(parseInput)) {
      guard case .valueNotFound = $0 as? DecodingError else {
        XCTFail()
        return
      }
    }

    formatStyle = RuleFormatStyle<DomainRule>().complete()
    parseInput = "# DOMAIN-SUFFIX,"
    XCTAssertThrowsError(try formatStyle.parse(parseInput)) {
      guard case .typeMismatch = $0 as? DecodingError else {
        XCTFail()
        return
      }
    }

    parseInput = "# DOMAIN,DIRECT"
    XCTAssertThrowsError(try formatStyle.parse(parseInput)) {
      guard case .valueNotFound = $0 as? DecodingError else {
        XCTFail()
        return
      }
    }

    formatStyle = RuleFormatStyle<DomainRule>()
    parseInput = "# DOMAIN,DIRECT"
    XCTAssertThrowsError(try formatStyle.parse(parseInput)) {
      guard case .dataCorrupted = $0 as? DecodingError else {
        XCTFail()
        return
      }
    }
  }
}
