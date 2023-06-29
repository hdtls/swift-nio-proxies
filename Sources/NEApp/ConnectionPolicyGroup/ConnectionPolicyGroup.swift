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

/// A type-erased connetion policy group representation value.
public struct AnyConnectionPolicyGroupRepresentation: Codable, Hashable, Sendable {

  public var name: String {
    base.name
  }

  public var policies: [String] { base.policies }

  /// The value wrapped by this instance.
  public var base: any ConnectionPolicyGroupRepresentation

  /// Creates a type-earsed connection policy group representation value that wraps the given instance.
  ///
  /// - Parameter base: A connection policy group representation value to wrap.
  public init(_ base: any ConnectionPolicyGroupRepresentation) {
    // Remove nested wrapping
    if let base = base as? AnyConnectionPolicyGroupRepresentation {
      self = base
    } else {
      self.base = base
    }
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let name = try container.decode(String.self, forKey: .name)
    let policies = try container.decode([String].self, forKey: .policies)
    let rawValue = try container.decode(String.self, forKey: .type)
    switch rawValue {
    case "select":
      base = ManuallySelectedPolicyGroup(name: name, policies: policies)
    default:
      throw DecodingError.dataCorrupted(
        DecodingError.Context(
          codingPath: [],
          debugDescription: "unknowned policy group type \(rawValue)"
        )
      )
    }
  }

  enum CodingKeys: CodingKey {
    case type
    case name
    case policies
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    switch base {
    case is ManuallySelectedPolicyGroup:
      try container.encode("select", forKey: .type)
    default:
      throw EncodingError.invalidValue(
        base,
        EncodingError.Context(
          codingPath: [CodingKeys.type],
          debugDescription: "unknowned policy group type"
        )
      )
    }
    try container.encode(base.name, forKey: .name)
    try container.encode(base.policies, forKey: .policies)
  }

  public static func == (
    lhs: AnyConnectionPolicyGroupRepresentation,
    rhs: AnyConnectionPolicyGroupRepresentation
  ) -> Bool {
    type(of: lhs.base) == type(of: rhs.base) && AnyHashable(lhs.base) == AnyHashable(rhs.base)
  }

  public func hash(into hasher: inout Hasher) {
    hasher.combine(base)
  }
}

extension AnyConnectionPolicyGroupRepresentation: ConnectionPolicyGroupRepresentation {}

/// One type of policy group, perform manully select policy as active policy.
public struct ManuallySelectedPolicyGroup: ConnectionPolicyGroupRepresentation {

  public let name: String

  public let policies: [String]

  public init(name: String, policies: [String]) {
    self.name = name
    self.policies = policies
  }
}
