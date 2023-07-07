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

import Foundation
import NEMisc

public struct DomainSetRule: ExternalResourcesRuleRepresentation, ParsableRuleRepresentation {

  public typealias FormatStyle = RuleFormatStyle<DomainSetRule>

  public typealias ParseStrategy = RuleFormatStyle<DomainSetRule>

  public static let identifier: RuleIdentifier = "DOMAIN-SET"

  public var disabled: Bool = false

  public var expression: String = ""

  public var policy: String = ""

  public var comment: String = ""

  @Protected public var externalResources: [String] = []

  public var description: String {
    FormatStyle().complete().format(self)
  }

  public init() {

  }

  public init?(_ description: String) {
    guard let parseOutput = try? ParseStrategy().complete().parse(description) else {
      return nil
    }
    self = parseOutput
  }

  public func match(_ expression: String) -> Bool {
    $externalResources.first {
      if $0.hasPrefix(".") {
        // Match domain and all sub-domains.
        return $0 == String($0[$0.index(after: $0.startIndex)...]) || ".\(expression)".hasSuffix($0)
      } else {
        return $0 == expression
      }
    } != nil
  }

  public mutating func loadAllRules(from file: URL) {
    guard let data = try? Data(contentsOf: file),
      let file = String(data: data, encoding: .utf8)
    else {
      return
    }

    $externalResources.write {
      $0 = file.split(separator: "\n")
        .compactMap {
          let literal = $0.trimmingCharacters(in: .whitespaces)
          guard !literal.isEmpty, !literal.hasPrefix("#"), !literal.hasPrefix(";") else {
            return nil
          }
          return literal
        }
    }
  }
}
