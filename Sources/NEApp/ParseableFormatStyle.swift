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

/// A type that can convert a given data type into a representation.
public protocol _ParseableFormatStyle: _FormatStyle {
  associatedtype Strategy: _ParseStrategy
  where Strategy.ParseInput == FormatOutput, Strategy.ParseOutput == FormatInput

  /// A `_ParseStrategy` that can be used to parse this `_FormatStyle`'s output
  var parseStrategy: Strategy { get }
}
