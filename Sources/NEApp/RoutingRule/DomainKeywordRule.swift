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

public struct DomainKeywordRule: ParsableRuleRepresentation {

  public typealias FormatStyle = RuleFormatStyle<DomainKeywordRule>

  public typealias ParseStrategy = RuleFormatStyle<DomainKeywordRule>

  public static let identifier: RuleIdentifier = "DOMAIN-KEYWORD"

  public var disabled: Bool = false

  public var expression: String = ""

  public var policy: String = ""

  public var comment: String = ""

  public var description: String {
    FormatStyle().complete().format(self)
  }

  public init() {

  }

  public init?(_ description: String) {
    guard
      let parseOutput = try? ParseStrategy().complete().parse(description)
    else {
      return nil
    }
    self = parseOutput
  }

  public func match(_ pattern: String) -> Bool {
    pattern.contains(expression)
  }
}
