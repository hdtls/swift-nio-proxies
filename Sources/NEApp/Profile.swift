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
import NEAppEssentials

/// A profile object that defines behavior and policies for a Netbot process.
public struct Profile: ProfileRepresentation, Codable, Hashable, Sendable {

  /// The rules contains in this configuration.
  public var routingRules: [AnyRoutingRule] = []

  /// A setting object that provides HTTP MitM settings for this process.
  public var manInTheMiddleSettings: ManInTheMiddleSettings = .init()

  /// A setting object that provides basic settings for this process.
  public var basicSettings: BasicSettings = .init()

  /// All proxy policy object contains in this configuration object.
  public var policies: [AnyConnectionPolicy] = []

  /// All selectable policy groups contains in this configuration object.
  public var policyGroups: [AnyConnectionPolicyGroup] = []

  /// Initialize an instance of `Profile` with the specified basicSettings, replicat, routingRules, manInTheMiddleSettings,
  /// polcies and policyGroups.
  public init(
    basicSettings: BasicSettings,
    routingRules: [AnyRoutingRule],
    manInTheMiddleSettings: ManInTheMiddleSettings,
    policies: [AnyConnectionPolicy],
    policyGroups: [AnyConnectionPolicyGroup]
  ) {
    self.basicSettings = basicSettings
    self.routingRules = routingRules
    self.manInTheMiddleSettings = manInTheMiddleSettings
    self.policies = policies
    self.policyGroups = policyGroups
  }

  /// Initialize an instance of `Profile` from specified url.
  ///
  /// - Parameter url: The url where `Profile` contents stored.
  public init(contentsOf url: URL) throws {
    let data = try Data(contentsOf: url)
    let jsonObject = try ProfileSerialization.jsonObject(with: data)
    let jsonData = try JSONSerialization.data(withJSONObject: jsonObject)
    self = try JSONDecoder().decode(Profile.self, from: jsonData)
  }

  /// Initialize an `Profile` with default values.
  public init() {

  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let ruleLiterals = try container.decodeIfPresent([String].self, forKey: .routingRules) ?? []
    let rules = ruleLiterals.compactMap { AnyRoutingRule($0) }
    let manInTheMiddleSettings = try container.decodeIfPresent(
      ManInTheMiddleSettings.self,
      forKey: .manInTheMiddleSettings
    )
    let basicSettings = try container.decodeIfPresent(BasicSettings.self, forKey: .basicSettings)
    var policies =
      try container.decodeIfPresent([AnyConnectionPolicy].self, forKey: .policies) ?? []
    // If the built-in policies do not exist, insert them at the beginning of the array
    if !policies.contains(where: { $0.name == "REJECT-TINYGIF" }) {
      policies.insert(AnyConnectionPolicy(RejectTinyGifPolicy()), at: 0)
    }
    if !policies.contains(where: { $0.name == "REJECT" }) {
      policies.insert(AnyConnectionPolicy(RejectPolicy()), at: 0)
    }
    if !policies.contains(where: { $0.name == "DIRECT" }) {
      policies.insert(AnyConnectionPolicy(DirectPolicy()), at: 0)
    }
    let policyGroups =
      try container.decodeIfPresent([AnyConnectionPolicyGroup].self, forKey: .policyGroups) ?? []

    self.init(
      basicSettings: basicSettings ?? .init(),
      routingRules: rules,
      manInTheMiddleSettings: manInTheMiddleSettings ?? .init(),
      policies: policies,
      policyGroups: policyGroups
    )
  }

  enum CodingKeys: CodingKey {
    case routingRules
    case manInTheMiddleSettings
    case basicSettings
    case policies
    case policyGroups
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(routingRules.map { $0.description }, forKey: .routingRules)
    try container.encode(manInTheMiddleSettings, forKey: .manInTheMiddleSettings)
    try container.encode(basicSettings, forKey: .basicSettings)
    try container.encode(policies, forKey: .policies)
    try container.encode(policyGroups, forKey: .policyGroups)
  }
}
