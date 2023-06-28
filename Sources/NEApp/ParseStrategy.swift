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

/// A type that can parse a representation of a given data type.
public protocol _ParseStrategy: Decodable, Encodable, Hashable {

  /// The type of the representation describing the data.
  associatedtype ParseInput

  /// The type of the data type.
  associatedtype ParseOutput

  /// Creates an instance of the `ParseOutput` type from `value`.
  func parse(_ value: ParseInput) throws -> ParseOutput
}
