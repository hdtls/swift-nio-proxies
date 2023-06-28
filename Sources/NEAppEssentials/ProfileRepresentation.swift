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

/// A profile object that defines behavior and policies for a Netbot process.
public protocol ProfileRepresentation: Hashable, Sendable {

  associatedtype RoutingRule: RoutingRuleRepresentation

  associatedtype ManInTheMiddleSettings: ManInTheMiddleSettingsRepresentation

  associatedtype BasicSettings: BasicSettingsRepresentation

  associatedtype ConnectionPolicy: ConnectionPolicyRepresentation

  associatedtype ConnectionPolicyGroup: ConnectionPolicyGroupRepresentation

  /// The rules contains in this configuration.
  var routingRules: [RoutingRule] { get }

  /// A setting object that provides HTTP MitM settings for this process.
  var manInTheMiddleSettings: ManInTheMiddleSettings { get }

  /// A setting object that provides basic settings for this process.
  var basicSettings: BasicSettings { get }

  /// All proxy policy object contains in this configuration object.
  var policies: [ConnectionPolicy] { get }

  /// All selectable policy groups contains in this configuration object.
  var policyGroups: [ConnectionPolicyGroup] { get }
}
