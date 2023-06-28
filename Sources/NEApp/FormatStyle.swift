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

/// A type that can convert a given data type into a representation.
public protocol _FormatStyle: Codable, Hashable {

  /// The type of data to format.
  associatedtype FormatInput

  /// The type of the formatted data.
  associatedtype FormatOutput

  /// Creates a `FormatOutput` instance from `value`.
  func format(_ value: FormatInput) -> FormatOutput

  /// If the format allows selecting a locale, returns a copy of this format with the new locale set. Default implementation returns an unmodified self.
  func locale(_ locale: Locale) -> Self
}

extension _FormatStyle {
  public func locale(_ locale: Locale) -> Self {
    return self
  }
}
