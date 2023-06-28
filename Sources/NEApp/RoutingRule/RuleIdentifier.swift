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

/// An identifier for rule type.
public struct RuleIdentifier: ExpressibleByStringLiteral, Hashable, Sendable {

  var rawValue: String

  public init(stringLiteral value: StringLiteralType) {
    rawValue = value
  }
}
