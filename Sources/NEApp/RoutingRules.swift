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
import MaxMindDB
import NEAppEssentials
import NEMisc

/// A `ExternalResourcesRuleRepresentation` is an object protocol that contains external rule resources.
public protocol ExternalResourcesRuleRepresentation: RoutingRuleRepresentation {

  associatedtype Resource

  var externalResources: [Resource] { get set }

  /// The external resources url.
  var externalResourcesURL: URL { get throws }

  /// The filename for this resources that been saved to local storage.
  var externalResourcesStorageName: String { get }

  /// Load all external resources from file url.
  /// - Parameter file: The file url contains external resources.
  mutating func loadAllRules(from file: URL)
}

extension ExternalResourcesRuleRepresentation {

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

public struct DomainKeywordRule: RoutingRuleRepresentation {

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

public struct DomainRule: RoutingRuleRepresentation {

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

public struct DomainSetRule: ExternalResourcesRuleRepresentation {

  public var expression: String

  public var policy: String

  public var disabled: Bool = false

  @Protected public var externalResources: [String] = []

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
    $externalResources.first(where: { $0 == expression || ".\(expression)".hasSuffix($0) }) != nil
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

public struct DomainSuffixRule: RoutingRuleRepresentation {

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

public struct GeoIPRule: RoutingRuleRepresentation, @unchecked Sendable {

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

public struct RuleSetRule: ExternalResourcesRuleRepresentation {

  public var expression: String

  public var policy: String

  public var disabled: Bool = false

  public var description: String {
    let prefix = disabled ? "# RULE-SET" : "RULE-SET"
    return prefix + ",\(expression),\(policy)"
  }

  @Protected public var externalResources: [any RoutingRuleRepresentation] = []

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

  public static func == (lhs: RuleSetRule, rhs: RuleSetRule) -> Bool {
    lhs.disabled == rhs.disabled && lhs.expression == rhs.expression && lhs.policy == rhs.policy
  }

  public func hash(into hasher: inout Hasher) {
    hasher.combine(disabled)
    hasher.combine(expression)
    hasher.combine(policy)
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
          AnyRoutingRule(String($0))
        }
    }
  }
}

public struct FinalRule: Hashable, RoutingRuleRepresentation {

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
}

public struct AnyRoutingRule: RoutingRuleRepresentation, Hashable, Sendable {

  public var disabled: Bool {
    base.disabled
  }

  public var expression: String {
    base.expression
  }

  public var policy: String {
    base.policy
  }

  public var description: String {
    base.description
  }

  public var base: any RoutingRuleRepresentation

  public init(_ base: any RoutingRuleRepresentation) {
    self.base = base
  }

  public init?(_ description: String) {
    var value = description.trimmingCharacters(in: .whitespaces)[...]
    value = value.hasPrefix("#") ? value.dropFirst() : value
    var components = value.split(separator: ",")
    let type = components.removeFirst()
    switch type {
    case "DOMAIN-KEYWORD":
      guard let parseOutput = DomainKeywordRule(description) else {
        return nil
      }
      self = .init(parseOutput)
    case "DOMAIN":
      guard let parseOutput = DomainRule(description) else {
        return nil
      }
      self = .init(parseOutput)
    case "DOMAIN-SET":
      guard let parseOutput = DomainSetRule(description) else {
        return nil
      }
      self = .init(parseOutput)
    case "DOMAIN-SUFFIX":
      guard let parseOutput = DomainSuffixRule(description) else {
        return nil
      }
      self = .init(parseOutput)
    case "GEOIP":
      guard let parseOutput = GeoIPRule(description) else {
        return nil
      }
      self = .init(parseOutput)
    case "RULE-SET":
      guard let parseOutput = RuleSetRule(description) else {
        return nil
      }
      self = .init(parseOutput)
    case "FINAL":
      guard let parseOutput = FinalRule(description) else {
        return nil
      }
      self = .init(parseOutput)
    default:
      return nil
    }
  }

  public static func == (lhs: AnyRoutingRule, rhs: AnyRoutingRule) -> Bool {
    AnyHashable(lhs.base) == AnyHashable(rhs.base)
  }

  public func hash(into hasher: inout Hasher) {
    hasher.combine(AnyHashable(base))
  }

  public func match(_ expression: String) -> Bool {
    base.match(expression)
  }
}
