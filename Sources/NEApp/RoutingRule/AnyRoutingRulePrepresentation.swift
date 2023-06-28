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

import NEAppEssentials

/// A type-ersed `RoutingRuleRepresentation`.
public struct AnyRoutingRuleRepresentation: RoutingRuleRepresentation, Hashable, Sendable {

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

  /// The value wrapped by this instance.
  public var base: any RoutingRuleRepresentation

  /// Creates a type-earsed routing rule representation value that wraps the given instance.
  ///
  /// - Parameter base: A routing rule representation value to wrap.
  public init(_ base: any RoutingRuleRepresentation) {
    // Remove nested wrapping
    if let base = base as? AnyRoutingRuleRepresentation {
      self = base
    } else {
      self.base = base
    }
  }

  public init?(_ description: String) {
    var value = description.trimmingCharacters(in: .whitespaces)[...]
    value = value.hasPrefix("#") ? value.dropFirst() : value
    var components = value.split(separator: ",")

    switch components.removeFirst() {
    case DomainKeywordRule.identifier.rawValue:
      guard let parseOutput = DomainKeywordRule(description) else {
        return nil
      }
      self = .init(parseOutput)
    case DomainRule.identifier.rawValue:
      guard let parseOutput = DomainRule(description) else {
        return nil
      }
      self = .init(parseOutput)
    case DomainSetRule.identifier.rawValue:
      guard let parseOutput = DomainSetRule(description) else {
        return nil
      }
      self = .init(parseOutput)
    case DomainSuffixRule.identifier.rawValue:
      guard let parseOutput = DomainSuffixRule(description) else {
        return nil
      }
      self = .init(parseOutput)
    case GeoIPRule.identifier.rawValue:
      guard let parseOutput = GeoIPRule(description) else {
        return nil
      }
      self = .init(parseOutput)
    case Ruleset.identifier.rawValue:
      guard let parseOutput = Ruleset(description) else {
        return nil
      }
      self = .init(parseOutput)
    case FinalRule.identifier.rawValue:
      guard let parseOutput = FinalRule(description) else {
        return nil
      }
      self = .init(parseOutput)
    default:
      return nil
    }
  }

  public static func == (lhs: AnyRoutingRuleRepresentation, rhs: AnyRoutingRuleRepresentation)
    -> Bool
  {
    type(of: lhs.base) == type(of: rhs.base) && AnyHashable(lhs.base) == AnyHashable(rhs.base)
  }

  public func hash(into hasher: inout Hasher) {
    hasher.combine(base)
  }

  public func match(_ expression: String) -> Bool {
    base.match(expression)
  }
}
