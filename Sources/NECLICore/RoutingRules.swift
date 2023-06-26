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

import Crypto
import Foundation
@_exported import MaxMindDB
import NECore

protocol CheckedParsableRule: RoutingRule {

  static var label: RuleSystem.Label { get }

  /// Validate whether given description can be parsed as `Self`.
  /// - Parameter description: The value to validate.
  static func validate(_ description: String) throws
}

extension CheckedParsableRule {

  static func validate(_ description: String) throws {
    let components = description.split(separator: ",").map {
      $0.trimmingCharacters(in: .whitespaces)
    }

    guard components.first == label.rawValue else {
      let label = RuleSystem.Label(rawValue: components.first ?? "")
      guard RuleSystem.labels.contains(label), let canBeParsedAs = RuleSystem.factory(for: label)
      else {
        throw ProfileSerializationError.failedToParseRule(reason: .unsupported)
      }
      throw ProfileSerializationError.failedToParseRule(
        reason: .failedToParseAs(Self.self, butCanBeParsedAs: canBeParsedAs)
      )
    }

    guard components.count >= 3 else {
      throw ProfileSerializationError.failedToParseRule(reason: .missingField)
    }
  }
}

/// A `ExternalRuleResources` is an object protocol that contains external resources
public protocol ExternalRuleResources {

  /// The external resources url.
  var externalResourcesURL: URL { get throws }

  /// The filename for this resources that been saved to local storage.
  var externalResourcesStorageName: String { get }

  /// Load all external resources from file url.
  /// - Parameter file: The file url contains external resources.
  mutating func loadAllRules(from file: URL)
}

extension ExternalRuleResources where Self: RoutingRule {

  public var externalResourcesURL: URL {
    get throws {
      guard let url = URL(string: expression) else {
        throw ProfileSerializationError.failedToParseRule(reason: .invalidExternalResources)
      }
      return url
    }
  }

  public var externalResourcesStorageName: String {
    guard let url = try? externalResourcesURL else {
      return ""
    }

    guard url.isFileURL else {
      return Insecure.SHA1.hash(data: Data(expression.utf8))
        .compactMap { String(format: "%02x", $0) }
        .joined()
    }
    return url.lastPathComponent
  }
}

public struct DomainKeywordRule: RoutingRule, CheckedParsableRule {

  static let label: RuleSystem.Label = .domainKeyword

  public var expression: String

  public var policy: String

  public var disabled: Bool = false

  public var description: String {
    let prefix = disabled ? "# DOMAIN-KEYWORD" : "DOMAIN-KEYWORD"
    return prefix + ",\(expression),\(policy)"
  }

  init() {
    expression = ""
    policy = ""
  }

  public init?(_ description: String) {
    var parseOutput = DomainKeywordRule()

    let value = description.trimmingCharacters(in: .whitespaces)
    parseOutput.disabled = value.hasPrefix("#")

    var components = value.split(separator: ",").map {
      $0.trimmingCharacters(in: .whitespaces)
    }

    let type = components.removeFirst()
    guard type == "DOMAIN-KEYWORD" else {
      return nil
    }

    guard let expression = components.first else {
      return nil
    }
    components.removeFirst()
    parseOutput.expression = expression

    guard let policy = components.first else {
      return nil
    }
    components.removeFirst()
    parseOutput.policy = policy

    self = parseOutput
  }

  public func match(_ pattern: String) -> Bool {
    pattern.contains(expression)
  }
}

public struct DomainRule: RoutingRule, CheckedParsableRule {

  static let label: RuleSystem.Label = .domain

  public var expression: String

  public var policy: String

  public var disabled: Bool = false

  public var description: String {
    let prefix = disabled ? "# DOMAIN" : "DOMAIN"
    return prefix + ",\(expression),\(policy)"
  }

  init() {
    expression = ""
    policy = ""
  }

  public init?(_ description: String) {
    var parseOutput = DomainRule()

    let value = description.trimmingCharacters(in: .whitespaces)
    parseOutput.disabled = value.hasPrefix("#")

    var components = value.split(separator: ",").map {
      $0.trimmingCharacters(in: .whitespaces)
    }

    let type = components.removeFirst()
    guard type == "DOMAIN" else {
      return nil
    }

    guard let expression = components.first else {
      return nil
    }
    components.removeFirst()
    parseOutput.expression = expression

    guard let policy = components.first else {
      return nil
    }
    components.removeFirst()
    parseOutput.policy = policy

    self = parseOutput
  }

  public func match(_ pattern: String) -> Bool {
    expression == pattern
  }
}

public struct DomainSetRule: ExternalRuleResources, RoutingRule, CheckedParsableRule {

  static let label: RuleSystem.Label = .domainSet

  public var expression: String

  public var policy: String

  public var disabled: Bool = false

  @Protected private var domains: [String] = []

  public var description: String {
    let prefix = disabled ? "# DOMAIN-SET" : "DOMAIN-SET"
    return prefix + ",\(expression),\(policy)"
  }

  init() {
    expression = ""
    policy = ""
  }

  public init?(_ description: String) {
    var parseOutput = DomainSetRule()

    let value = description.trimmingCharacters(in: .whitespaces)
    parseOutput.disabled = value.hasPrefix("#")

    var components = value.split(separator: ",").map {
      $0.trimmingCharacters(in: .whitespaces)
    }

    let type = components.removeFirst()
    guard type == "DOMAIN-SET" else {
      return nil
    }

    guard let expression = components.first else {
      return nil
    }
    components.removeFirst()
    parseOutput.expression = expression

    guard let policy = components.first else {
      return nil
    }
    components.removeFirst()
    parseOutput.policy = policy

    self = parseOutput
  }

  public func match(_ expression: String) -> Bool {
    $domains.first(where: { $0 == expression || ".\(expression)".hasSuffix($0) }) != nil
  }

  public mutating func loadAllRules(from file: URL) {
    guard let data = try? Data(contentsOf: file),
      let file = String(data: data, encoding: .utf8)
    else {
      return
    }

    $domains.write {
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

public struct DomainSuffixRule: RoutingRule, CheckedParsableRule {

  static let label: RuleSystem.Label = .domainSuffix

  public var expression: String

  public var policy: String

  public var disabled: Bool = false

  public var description: String {
    let prefix = disabled ? "# DOMAIN-SUFFIX" : "DOMAIN-SUFFIX"
    return prefix + ",\(expression),\(policy)"
  }

  init() {
    expression = ""
    policy = ""
  }

  public init?(_ description: String) {
    var parseOutput = DomainSuffixRule()

    let value = description.trimmingCharacters(in: .whitespaces)
    parseOutput.disabled = value.hasPrefix("#")

    var components = value.split(separator: ",").map {
      $0.trimmingCharacters(in: .whitespaces)
    }

    let type = components.removeFirst()
    guard type == "DOMAIN-SUFFIX" else {
      return nil
    }

    guard let expression = components.first else {
      return nil
    }
    components.removeFirst()
    parseOutput.expression = expression

    guard let policy = components.first else {
      return nil
    }
    components.removeFirst()
    parseOutput.policy = policy

    self = parseOutput
  }

  public func match(_ pattern: String) -> Bool {
    // e.g. apple.com should match *.apple.com and apple.com
    // should not match *apple.com.
    expression == pattern || ".\(pattern)".hasSuffix(expression)
  }
}

public struct GeoIPRule: RoutingRule, CheckedParsableRule, @unchecked Sendable {

  static let label: RuleSystem.Label = .geoIp

  public var expression: String

  public var policy: String

  public var disabled: Bool = false

  @Protected public static var database: MaxMindDB?

  public var description: String {
    let prefix = disabled ? "# GEOIP" : "GEOIP"
    return prefix + ",\(expression),\(policy)"
  }

  init() {
    expression = ""
    policy = ""
  }

  public init?(_ description: String) {
    var parseOutput = GeoIPRule()

    let value = description.trimmingCharacters(in: .whitespaces)
    parseOutput.disabled = value.hasPrefix("#")

    var components = value.split(separator: ",").map {
      $0.trimmingCharacters(in: .whitespaces)
    }

    let type = components.removeFirst()
    guard type == "GEOIP" else {
      return nil
    }

    guard let expression = components.first else {
      return nil
    }
    components.removeFirst()
    parseOutput.expression = expression

    guard let policy = components.first else {
      return nil
    }
    components.removeFirst()
    parseOutput.policy = policy

    self = parseOutput
  }

  public func match(_ pattern: String) -> Bool {
    Self.$database.read {
      let dictionary = try? $0?.lookup(ipAddress: pattern) as? [String: [String: Any]]
      let country = dictionary?["country"]
      let countryCode = country?["iso_code"] as? String
      return self.expression == countryCode
    }
  }
}

public struct RuleSetRule: ExternalRuleResources, RoutingRule, CheckedParsableRule {

  static let label: RuleSystem.Label = .ruleSet

  public var expression: String

  public var policy: String

  public var disabled: Bool = false

  public var description: String {
    let prefix = disabled ? "# RULE-SET" : "RULE-SET"
    return prefix + ",\(expression),\(policy)"
  }

  @Protected private var standardRules: [RoutingRule] = []

  init() {
    expression = ""
    policy = ""
  }

  public init?(_ description: String) {
    var parseOutput = RuleSetRule()

    let value = description.trimmingCharacters(in: .whitespaces)
    parseOutput.disabled = value.hasPrefix("#")

    var components = value.split(separator: ",").map {
      $0.trimmingCharacters(in: .whitespaces)
    }

    let type = components.removeFirst()
    guard type == "RULE-SET" else {
      return nil
    }

    guard let expression = components.first else {
      return nil
    }
    components.removeFirst()
    parseOutput.expression = expression

    guard let policy = components.first else {
      return nil
    }
    components.removeFirst()
    parseOutput.policy = policy

    self = parseOutput
  }

  public func match(_ expression: String) -> Bool {
    $standardRules.first(where: { $0.match(expression) }) != nil
  }

  public mutating func loadAllRules(from file: URL) {
    guard let data = try? Data(contentsOf: file),
      let file = String(data: data, encoding: .utf8)
    else {
      return
    }

    $standardRules.write {
      $0 = file.split(separator: "\n")
        .compactMap {
          let literal = $0.trimmingCharacters(in: .whitespaces)
          guard !literal.isEmpty, !literal.hasPrefix("#"), !literal.hasPrefix(";") else {
            return nil
          }
          let label = String(literal.split(separator: ",").first ?? "")
          let description = literal + ",\(policy)"
          guard let factory = RuleSystem.factory(for: .init(rawValue: label)) else {
            return nil
          }
          return factory.init(description)
        }
    }
  }
}

public struct FinalRule: Hashable, RoutingRule, CheckedParsableRule {

  public var expression: String

  public var policy: String

  public var disabled: Bool = false

  public var description: String {
    let prefix = disabled ? "# FINAL" : "FINAL"
    return prefix + ",\(policy)"
  }

  public init?(_ description: String) {
    // Rule definitions are comma-separated.
    let components = description.components(separatedBy: ",").map {
      $0.trimmingCharacters(in: .whitespaces)
    }

    guard components.count == 2, components.first == "FINAL" else {
      return nil
    }

    expression = ""
    policy = components[1]
  }

  public func match(_ pattern: String) -> Bool {
    true
  }

  static let label: RuleSystem.Label = .final

  static func validate(_ description: String) throws {
    let components = description.split(separator: ",").map {
      $0.trimmingCharacters(in: .whitespaces)
    }

    guard components.first == label.rawValue else {
      let label = RuleSystem.Label(rawValue: components.first ?? "")
      guard RuleSystem.labels.contains(label), let canBeParsedAs = RuleSystem.factory(for: label)
      else {
        throw ProfileSerializationError.failedToParseRule(reason: .unsupported)
      }
      throw ProfileSerializationError.failedToParseRule(
        reason: .failedToParseAs(Self.self, butCanBeParsedAs: canBeParsedAs)
      )
    }

    guard components.count >= 2 else {
      throw ProfileSerializationError.failedToParseRule(reason: .missingField)
    }
  }
}
