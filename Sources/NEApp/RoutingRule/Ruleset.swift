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

public struct Ruleset: ExternalResourcesRuleRepresentation, ParsableRuleRepresentation {

  public typealias FormatStyle = RuleFormatStyle<Ruleset>

  public typealias ParseStrategy = RuleFormatStyle<Ruleset>

  public static let identifier: RuleIdentifier = "RULE-SET"

  public var disabled: Bool = false

  public var expression: String = ""

  public var policy: String = ""

  public var comment: String = ""

  @Protected public var externalResources: [AnyRoutingRuleRepresentation] = []

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
    $externalResources.first(where: { $0.match(expression) }) != nil
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
          let description = "\($0),\(policy)"
          return AnyRoutingRuleRepresentation(description)
        }
    }
  }
}
