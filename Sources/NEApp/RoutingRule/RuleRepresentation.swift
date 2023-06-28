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

import Crypto
import Foundation
import NEAppEssentials

/// A routing rule representation which can be parse with specified FormatStyle and ParseStrategy.
public protocol ParsableRuleRepresentation: RoutingRuleRepresentation {

  /// Type identifier for this rule.
  static var identifier: RuleIdentifier { get }

  var disabled: Bool { get set }

  var expression: String { get set }

  var policy: String { get set }

  /// Comment for this rule.
  var comment: String { get set }

  /// Default initializer.
  init()
}

/// A `ExternalResourcesRuleRepresentation` is an object protocol that contains external rule resources.
public protocol ExternalResourcesRuleRepresentation: RoutingRuleRepresentation {

  associatedtype Resources

  /// External resources contains in this rule.
  var externalResources: Resources { get set }

  /// The external resources url.
  var externalResourcesURL: URL { get throws }

  /// The filename for this resources that been saved to local storage.
  var externalResourcesStorageName: String { get }

  /// Load all external resources from file url.
  /// - Parameter file: The file url contains external resources.
  mutating func loadAllRules(from file: URL)
}

extension ExternalResourcesRuleRepresentation {

  public var externalResourcesURL: URL {
    get throws {
      guard let url = URL(string: expression) else {
        throw ProfileSerializationError.failedToParseRule(reason: .invalidExternalResources)
      }
      return url
    }
  }

  public var externalResourcesStorageName: String {
    guard let url = try? externalResourcesURL else {
      return ""
    }

    guard url.isFileURL else {
      return Insecure.SHA1.hash(data: Data(expression.utf8))
        .compactMap { String(format: "%02x", $0) }
        .joined()
    }
    return url.lastPathComponent
  }
}
