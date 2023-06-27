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

import NEAppEssentials

private enum AnyPolicyGroupType: CaseIterable, Sendable {
  case selection
}

struct AnyPolicyGroup: ConnectionPolicyGroup, Codable {

  fileprivate var type: AnyPolicyGroupType = .selection
  var name: String { base.name }
  var policies: [String] { base.policies }
  var base: ConnectionPolicyGroup

  enum CodingKeys: String, CodingKey {
    case type
    case name
    case policies
  }

  init(_ base: ConnectionPolicyGroup) {
    self.base = base
    switch base {
    case is ManuallySelectedPolicyGroup:
      type = .selection
    default:
      fatalError()
    }
  }

  init(name: String, policies: [String]) {
    self.base = ManuallySelectedPolicyGroup(name: name, policies: policies)
  }

  init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let rawValue = try container.decode(String.self, forKey: .type)
    let name = try container.decode(String.self, forKey: .name)
    let policies = try container.decode([String].self, forKey: .policies)

    switch rawValue {
    case "select":
      base = ManuallySelectedPolicyGroup(name: name, policies: policies)
    default:
      throw DecodingError.dataCorrupted(
        DecodingError.Context(
          codingPath: [CodingKeys.type],
          debugDescription: "unsupported policy group type \(rawValue)"
        )
      )
    }
  }

  func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    switch base {
    case is ManuallySelectedPolicyGroup:
      try container.encode("select", forKey: .type)
    default:
      throw EncodingError.invalidValue(
        base,
        EncodingError.Context(
          codingPath: [CodingKeys.type],
          debugDescription: "unsupported policy group type"
        )
      )
    }
    try container.encode(base.name, forKey: .name)
    try container.encode(base.policies, forKey: .policies)
  }
}

public struct ManuallySelectedPolicyGroup: ConnectionPolicyGroup, Hashable {

  public let name: String

  public let policies: [String]

  public init(name: String, policies: [String]) {
    self.name = name
    self.policies = policies
  }
}
