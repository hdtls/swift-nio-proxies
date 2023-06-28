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

/// A `RoutingRuleRepresentation` statement consists of a set of conditions that are compared against the traffic that is being sent.
/// When a match is found, policy lookup stops and the traffic is assigned the actions that are associated with the rule.
public protocol RoutingRuleRepresentation: Hashable, LosslessStringConvertible, Sendable {

  /// A boolean value determinse whether this rule is enabled or disabled.
  var disabled: Bool { get }

  /// The expression fot this rule.
  ///
  /// If rule is collection expression is used to save external resources url string.
  var expression: String { get }

  /// The policy pointed to by the rule.
  var policy: String { get }

  /// Rule evaluating function to determinse whether this rule match the given expression.
  /// - Returns: True if match else false.
  func match(_ expression: String) -> Bool
}
