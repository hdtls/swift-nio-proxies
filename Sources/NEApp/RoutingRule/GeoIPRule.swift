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

import MaxMindDB
import NEMisc

public struct GeoIPRule: ParsableRuleRepresentation, @unchecked Sendable {

  public typealias FormatStyle = RuleFormatStyle<GeoIPRule>

  public typealias ParseStrategy = RuleFormatStyle<GeoIPRule>

  public static let identifier: RuleIdentifier = "GEOIP"

  public var disabled: Bool = false

  public var expression: String = ""

  public var policy: String = ""

  public var comment: String = ""

  @Protected public static var database: MaxMindDB?

  public var description: String {
    FormatStyle().complete().format(self)
  }

  public init() {

  }

  public init?(_ description: String) {
    guard let parseOutput = try? ParseStrategy().complete().parse(description) else {
      return nil
    }
    self = parseOutput
  }

  public func match(_ pattern: String) -> Bool {
    Self.$database.read {
      let dictionary = try? $0?.lookup(ipAddress: pattern) as? [String: [String: Any]]
      let country = dictionary?["country"]
      let countryCode = country?["iso_code"] as? String
      return self.expression == countryCode
    }
  }
}
