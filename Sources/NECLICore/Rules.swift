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
@_exported import NECore

protocol CheckedParsableRule: ParsableRule {

  static var label: RuleSystem.Label { get }

  /// Validate whether given description can be parsed as `Self`.
  /// - Parameter description: The value to validate.
  static func validate(_ description: String) throws
}

extension CheckedParsableRule {

  public init?(_ description: String) {
    // Rule definitions are comma-separated except comments, and comment are
    // always at the end of the rule and followed by //.
    //
    // Becase comments may contain commas, so we parse comments first.
    var components = description.split(separator: ",").map {
      $0.trimmingCharacters(in: .whitespaces)
    }

    let type = components.removeFirst()

    guard type == Self.label.rawValue else {
      return nil
    }

    let countOfRequiredFields = type == RuleSystem.Label.final.rawValue ? 1 : 2
    guard components.count >= countOfRequiredFields else {
      return nil
    }

    let expression = type != RuleSystem.Label.final.rawValue ? components.removeFirst() : ""

    let policy = components.removeFirst()

    self.init(expression: expression, policy: policy)
  }

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

extension ExternalRuleResources where Self: ParsableRule {

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

public struct DomainKeywordRule: ParsableRule, CheckedParsableRule {

  static let label: RuleSystem.Label = .domainKeyword

  public var expression: String

  public var policy: String

  public var description: String {
    "\(Self.label.rawValue),\(expression),\(policy)"
  }

  public init(expression: String, policy: String) {
    self.expression = expression
    self.policy = policy
  }

  public func match(_ pattern: String) -> Bool {
    pattern.contains(expression)
  }
}

public struct DomainRule: ParsableRule, CheckedParsableRule {

  static let label: RuleSystem.Label = .domain

  public var expression: String

  public var policy: String

  public var description: String {
    "\(Self.label.rawValue),\(expression),\(policy)"
  }

  public init(expression: String, policy: String) {
    self.expression = expression
    self.policy = policy
  }

  public func match(_ pattern: String) -> Bool {
    expression == pattern
  }
}

public struct DomainSetRule: ExternalRuleResources, ParsableRule, CheckedParsableRule {

  static let label: RuleSystem.Label = .domainSet

  public var expression: String

  public var policy: String

  @Protected private var domains: [String] = []

  public var description: String {
    "\(Self.label.rawValue),\(expression),\(policy)"
  }

  public init(expression: String, policy: String) {
    self.expression = expression
    self.policy = policy
  }

  public func match(_ expression: String) -> Bool {
    domains.first {
      $0 == expression || ".\(expression)".hasSuffix($0)
    } != nil
  }

  public mutating func loadAllRules(from file: URL) {
    guard let data = try? Data(contentsOf: file),
      let file = String(data: data, encoding: .utf8)
    else {
      return
    }

    domains = file.split(separator: "\n")
      .compactMap {
        let literal = $0.trimmingCharacters(in: .whitespaces)
        guard !literal.isEmpty, !literal.hasPrefix("#"), !literal.hasPrefix(";") else {
          return nil
        }
        return literal
      }
  }
}

public struct DomainSuffixRule: ParsableRule, CheckedParsableRule {

  static let label: RuleSystem.Label = .domainSuffix

  public var expression: String

  public var policy: String

  public var description: String {
    "\(Self.label.rawValue),\(expression),\(policy)"
  }

  public init(expression: String, policy: String) {
    self.expression = expression
    self.policy = policy
  }

  public func match(_ pattern: String) -> Bool {
    // e.g. apple.com should match *.apple.com and apple.com
    // should not match *apple.com.
    expression == pattern || ".\(pattern)".hasSuffix(expression)
  }
}

public struct GeoIPRule: ParsableRule, CheckedParsableRule, @unchecked Sendable {

  static let label: RuleSystem.Label = .geoIp

  public var expression: String

  public var policy: String

  @Protected public static var database: MaxMindDB?

  public var description: String {
    "\(Self.label.rawValue),\(expression),\(policy)"
  }

  public init(expression: String, policy: String) {
    self.expression = expression
    self.policy = policy
  }

  public func match(_ pattern: String) -> Bool {
    do {
      let dictionary =
        try Self.database?.lookup(ipAddress: pattern) as? [String: [String: Any]]
      let country = dictionary?["country"]
      let countryCode = country?["iso_code"] as? String
      return self.expression == countryCode
    } catch {
      return false
    }
  }
}

//public struct IPRangeRule: ParsableRule, Equatable, Hashable, Identifiable {
//
//    public let id: UUID = .init()
//
//    var type: String
//
//    public var expression: String
//
//    public var policy: String
//
//    public var description: String {
//        "\(type),\(expression),\(policy)"
//    }
//
//    public mutating func validate() throws {
//        guard RuleType(rawValue: type) != nil else {
//            throw ProfileSerializationError.failedToParseRule(reason: .unsupported)
//        }
//    }
//
//    public func match(_ pattern: String) -> Bool {
//        pattern.contains(expression)
//    }
//
//    public init?(_ description: String) {
//        // Rule definitions are comma-separated.
//        let components = description.components(separatedBy: ",").map { $0.trimmingCharacters(in: .whitespaces) }
//
//        guard components.count == 3 else {
//            return nil
//        }
//
//        type = components.first!
//        expression = components[1]
//        policy = components.last!
//    }
//}

public struct RuleSetRule: ExternalRuleResources, ParsableRule, CheckedParsableRule {

  static let label: RuleSystem.Label = .ruleSet

  public var expression: String

  public var policy: String

  public var description: String {
    "\(Self.label.rawValue),\(expression),\(policy)"
  }

  @Protected private var standardRules: [ParsableRule] = []

  public init(expression: String, policy: String) {
    self.expression = expression
    self.policy = policy
  }

  public func match(_ expression: String) -> Bool {
    standardRules.first(where: { $0.match(expression) }) != nil
  }

  public mutating func loadAllRules(from file: URL) {
    guard let data = try? Data(contentsOf: file),
      let file = String(data: data, encoding: .utf8)
    else {
      return
    }
    standardRules = file.split(separator: "\n")
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

extension FinalRule: CheckedParsableRule {

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
