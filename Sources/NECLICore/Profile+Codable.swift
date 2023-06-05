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
@_exported import NECore

extension Profile: Codable {

  enum CodingKeys: String, CodingKey {
    case rules
    case manInTheMiddleSettings
    case basicSettings
    case policies
    case policyGroups
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)

    let ruleLiterals = try container.decodeIfPresent([String].self, forKey: .rules) ?? []
    let rules = try ruleLiterals.compactMap {
      var components = $0.split(separator: ",")
      let id = String(components.removeFirst())
      guard let factory = RuleSystem.factory(for: .init(rawValue: id)) else {
        throw ProfileSerializationError.failedToParseRule(reason: .unsupported)
      }
      try factory.validate($0)
      return factory.init($0)
    }
    let manInTheMiddleSettings = try container.decodeIfPresent(
      ManInTheMiddleSettings.self,
      forKey: .manInTheMiddleSettings
    )
    let basicSettings = try container.decodeIfPresent(
      BasicSettings.self,
      forKey: .basicSettings
    )
    var policies =
      try container.decodeIfPresent([AnyConnectionPolicy].self, forKey: .policies)?.map {
        $0.base
      } ?? []
    // If the built-in policies do not exist, insert them at the beginning of the array
    if !policies.contains(where: { $0.name == "REJECT-TINYGIF" }) {
      policies.insert(RejectTinyGifPolicy(), at: 0)
    }
    if !policies.contains(where: { $0.name == "REJECT" }) {
      policies.insert(RejectPolicy(), at: 0)
    }
    if !policies.contains(where: { $0.name == "DIRECT" }) {
      policies.insert(DirectPolicy(), at: 0)
    }
    let policyGroups = try container.decodeIfPresent([AnyPolicyGroup].self, forKey: .policyGroups)

    self.init(
      basicSettings: basicSettings ?? .init(),
      rules: rules,
      manInTheMiddleSettings: manInTheMiddleSettings ?? .init(),
      policies: policies,
      policyGroups: policyGroups ?? []
    )
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(rules.map { $0.description }, forKey: .rules)
    try container.encode(manInTheMiddleSettings, forKey: .manInTheMiddleSettings)
    try container.encode(basicSettings, forKey: .basicSettings)
    try container.encode(policies.map(AnyConnectionPolicy.init), forKey: .policies)
    try container.encode(
      policyGroups.map {
        AnyPolicyGroup(name: $0.name, policies: $0.policies)
      },
      forKey: .policyGroups
    )
  }
}

extension Profile {

  /// Initialize an instance of `Profile` from specified url.
  /// - Parameter url: The url where `Profile` contents stored.
  public init(contentsOf url: URL) throws {
    let data = try Data(contentsOf: url)
    let jsonObject = try ProfileSerialization.jsonObject(with: data)
    let jsonData = try JSONSerialization.data(withJSONObject: jsonObject)
    self = try JSONDecoder().decode(Profile.self, from: jsonData)
  }
}

/// PolicyGroup coding wrapper.
struct AnyPolicyGroup: PolicyGroup, Codable {
  var name: String
  var policies: [String]

  enum CodingKeys: String, CodingKey {
    case name
    case policies
  }
}
