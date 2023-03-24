//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2022 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NECore
import NIOConcurrencyHelpers

enum RuleSystem {

  /// Label object use to identifier `ParsableRule` metadata.
  struct Label: Hashable, RawRepresentable, ExpressibleByStringLiteral {

    public var rawValue: String

    public init(rawValue: String) {
      self.rawValue = rawValue
    }

    public init(stringLiteral value: String) {
      self.rawValue = value
    }
  }

  /// The object to store parsable rule metatype.
  final private class Registry {

    private var storage: [Label: CheckedParsableRule.Type] = [:]

    let lock: NIOLock = .init()

    /// Labels for all registered rules.
    var allLabels: [Label] {
      lock.withLock {
        Array(storage.keys)
      }
    }

    init() {
      use(DomainKeywordRule.self, as: .domainKeyword)
      use(DomainRule.self, as: .domain)
      use(DomainSetRule.self, as: .domainSet)
      use(DomainSuffixRule.self, as: .domainSuffix)
      use(FinalRule.self, as: .final)
      use(GeoIPRule.self, as: .geoIp)
      use(RuleSetRule.self, as: .ruleSet)
    }

    func factory(for id: Label) -> CheckedParsableRule.Type? {
      lock.withLock {
        storage[id]
      }
    }

    func use(_ type: CheckedParsableRule.Type, as id: Label) {
      lock.withLock {
        storage[id] = type
      }
    }
  }

  private static let registry: Registry = .init()

  /// Request rule metadata with specified id value.
  /// - Parameter id: The id use to lookup rule metadata.
  /// - Returns: `ParsableRule` type if find or nil.
  static func factory(for id: Label) -> CheckedParsableRule.Type? {
    registry.factory(for: id)
  }

  /// Register rule metatype with specified id.
  /// - Parameters:
  ///   - type: The rule metatype.
  ///   - id: The id used to register this rule metatype.
  static func use(_ type: CheckedParsableRule.Type, as id: Label) {
    registry.use(type, as: id)
  }

  /// Labels for all registered rules.
  static var labels: [Label] {
    registry.allLabels
  }
}

extension RuleSystem.Label {

  /// Label for `DOMAIN` rule.
  static var domain: RuleSystem.Label { "DOMAIN" }

  /// Label for `DOMAIN-SUFFIX` rule.
  static var domainSuffix: RuleSystem.Label { "DOMAIN-SUFFIX" }

  /// Label for `DOMAIN-KEYWORD` rule.
  static var domainKeyword: RuleSystem.Label { "DOMAIN-KEYWORD" }

  /// Label for `DOMAIN-SET` rule.
  static var domainSet: RuleSystem.Label { "DOMAIN-SET" }

  /// Label for `RULE-SET` rule.
  static var ruleSet: RuleSystem.Label { "RULE-SET" }

  /// Label for `GEOIP` rule.
  static var geoIp: RuleSystem.Label { "GEOIP" }

  /// Label for `FINAL` rule.
  static var final: RuleSystem.Label { "FINAL" }
}
