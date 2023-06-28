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

/// Strategies for formatting a `ParsableRuleRepresentation`.
public struct RuleFormatStyle<Value>: Sendable where Value: ParsableRuleRepresentation {

  var fields = Set<RuleField>()

  var style: RuleStyle?

  /// Creates RuleFormatStyle with specified rule style.
  ///
  /// - Parameter style: The rule style. Defaults to nil.
  public init(style: RuleStyle? = nil) {
    self.style = style
  }
}

public struct RuleField: Codable, Hashable, Sendable {

  /// `Rule.disabled` filed.
  public static let flag = RuleField(rawValue: 0)

  /// `Rule.symbols` filed.
  public static let symbols = RuleField(rawValue: 1)

  /// `Rule.expression` filed.
  public static let expression = RuleField(rawValue: 2)

  /// `Rule.policy` filed.
  public static let policy = RuleField(rawValue: 3)

  /// `Rule.comment` filed.
  public static let comment = RuleField(rawValue: 4)

  public var rawValue: Int
}

extension RuleFormatStyle {

  /// Create new FormatStyle by include `flag` field.
  public func flag() -> Self {
    var new = self
    new.fields.insert(.flag)
    return new
  }

  /// Create new FormatStyle by include `symbols` field.
  public func symbols() -> Self {
    var new = self
    new.fields.insert(.symbols)
    return new
  }

  /// Create new FormatStyle by include `expression` field.
  public func expression() -> Self {
    var new = self
    new.fields.insert(.expression)
    return new
  }

  /// Create new FormatStyle by include `policy` field.
  public func policy() -> Self {
    var new = self
    new.fields.insert(.policy)
    return new
  }

  /// Create new FormatStyle by include `comment` field.
  public func comment() -> Self {
    var new = self
    new.fields.insert(.comment)
    return new
  }

  /// Create new FormatStyle by include `flag`, `symbols`, `policy`, and `comment` fields.
  public func omitted() -> Self {
    var new = self
    new.fields.insert(.flag)
    new.fields.insert(.symbols)
    new.fields.insert(.policy)
    new.fields.insert(.comment)
    return new
  }

  /// Create new FormatStyle by include `flag`, `symbols`, `policy`, `expression` and `comment` fields.
  public func complete() -> Self {
    var new = self
    new.fields.insert(.flag)
    new.fields.insert(.symbols)
    new.fields.insert(.expression)
    new.fields.insert(.policy)
    new.fields.insert(.comment)
    return new
  }
}

extension RuleFormatStyle: _FormatStyle {
  public func format(_ value: Value) -> String {
    var components: [String] = []
    if fields.contains(.flag) {
      if value.disabled {
        components.append("# ")
      }
    }
    if fields.contains(.symbols) {
      components.append(Value.identifier.rawValue)
    }

    switch style {
    case .some(.complete), .none:
      if fields.contains(.expression) {
        if fields.contains(.symbols) {
          components.append(",")
        }
        components.append(value.expression)
      }
      if fields.contains(.policy) {
        if fields.contains(.symbols) || fields.contains(.expression) {
          components.append(",")
        }
        components.append(value.policy)
      }
    case .some(.omitted):
      if fields.contains(.policy) {
        if fields.contains(.symbols) {
          components.append(",")
        }
        components.append(value.policy)
      }
    default:
      break
    }

    if fields.contains(.comment) {
      if !value.comment.isEmpty {
        components.append(" // ")
        components.append(value.comment)
      }
    }

    return components.joined()
  }
}

extension RuleFormatStyle: _ParseStrategy {
  public func parse(_ value: String) throws -> Value {
    var parseOutput = Value()

    var value = value.trimmingCharacters(in: .whitespaces)[...]

    var disabled = false
    if value.hasPrefix("#") {
      disabled = true
      value = value.dropFirst()
    }
    if fields.contains(.flag) {
      parseOutput.disabled = disabled
    }

    var position: String.Index! = value.firstIndex(of: ",")
    guard position != nil else {
      switch style {
      case .some(.complete), .none:
        if fields.contains(.expression) {
          throw DecodingError.valueNotFound(
            String.self,
            DecodingError.Context(
              codingPath: [_CodinKey(stringValue: "expression")!],
              debugDescription: "expression field is missing"
            )
          )
        } else {
          throw DecodingError.dataCorrupted(
            DecodingError.Context(codingPath: [], debugDescription: "missing fields")
          )
        }
      case .some(.omitted):
        if fields.contains(.policy) {
          throw DecodingError.valueNotFound(
            String.self,
            DecodingError.Context(
              codingPath: [_CodinKey(stringValue: "policy")!],
              debugDescription: "policy field is missing"
            )
          )
        } else {
          throw DecodingError.dataCorrupted(
            DecodingError.Context(codingPath: [], debugDescription: "missing fields")
          )
        }
      default:
        throw DecodingError.dataCorrupted(
          DecodingError.Context(
            codingPath: [],
            debugDescription: "missing fields"
          )
        )
      }
    }

    let symbols = value[..<position].trimmingCharacters(in: .whitespaces)
    guard symbols == Value.identifier.rawValue else {
      var codingPath: [CodingKey] = []
      if fields.contains(.symbols) {
        codingPath.append(_CodinKey(stringValue: "symbols")!)
      }
      throw DecodingError.typeMismatch(
        Value.self,
        DecodingError.Context(
          codingPath: codingPath,
          debugDescription: "try to parse \(Value.self) but found symbols \(symbols)"
        )
      )
    }

    value = value[value.index(after: position)...]

    switch style {
    case .some(.complete), .none:
      position = value.firstIndex(of: ",")
      guard position != nil else {
        if fields.contains(.policy) {
          throw DecodingError.valueNotFound(
            String.self,
            DecodingError.Context(
              codingPath: [_CodinKey(stringValue: "policy")!],
              debugDescription: "policy field is missing"
            )
          )
        } else {
          throw DecodingError.dataCorrupted(
            DecodingError.Context(codingPath: [], debugDescription: "missing fields")
          )
        }
      }
      if fields.contains(.expression) {
        parseOutput.expression = value[..<position].trimmingCharacters(in: .whitespaces)
      }

      value = value[value.index(after: position)...]

      fallthrough
    case .some(.omitted):
      var policy = ""
      var comment = ""
      if let lowerBound = value.range(of: "//")?.lowerBound {
        policy = value[..<lowerBound].trimmingCharacters(in: .whitespaces)
        value = value[value.index(lowerBound, offsetBy: 2)...]
        comment = value.trimmingCharacters(in: .whitespaces)
      } else {
        policy = value.trimmingCharacters(in: .whitespaces)
      }

      if fields.contains(.policy) {
        parseOutput.policy = policy
      }

      if fields.contains(.comment) {
        parseOutput.comment = comment
      }

      return parseOutput
    default:
      throw DecodingError.dataCorrupted(
        DecodingError.Context(codingPath: [], debugDescription: "unknown rule style")
      )
    }
  }
}

extension RuleFormatStyle: _ParseableFormatStyle {
  public var parseStrategy: RuleFormatStyle<Value> {
    self
  }
}

extension RuleFormatStyle: Codable, Hashable {

  enum CodingKeys: CodingKey {
    case fields
    case style
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(fields, forKey: .fields)
    try container.encodeIfPresent(style, forKey: .style)
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    fields = try container.decode(Set<RuleField>.self, forKey: .fields)
    style = try container.decodeIfPresent(RuleStyle.self, forKey: .style)
  }
}

public struct RuleStyle: Codable, Hashable, Sendable {

  /// Excludes the expression part.
  public static let omitted: RuleStyle = RuleStyle(rawValue: 0)

  /// Include all required fields.
  /// e.g., `# DOMAIN,example.com,DIRECT // The rule for direct example.com to DIRECT policy.`
  public static let complete: RuleStyle = RuleStyle(rawValue: 1)

  let rawValue: Int
}

struct _CodinKey: CodingKey {

  enum Representation {
    case string(String)
    case int(Int)
    case index(Int)
    case both(String, Int)
  }

  let representation: Representation

  init?(stringValue: String) {
    self.representation = .string(stringValue)
  }

  init?(intValue: Int) {
    self.representation = .int(intValue)
  }

  init(index: Int) {
    self.representation = .index(index)
  }

  init(stringValue: String, intValue: Int?) {
    if let intValue {
      self.representation = .both(stringValue, intValue)
    } else {
      self.representation = .string(stringValue)
    }
  }

  var stringValue: String {
    switch representation {
    case let .string(str): return str
    case let .int(int): return "\(int)"
    case let .index(index): return "Index \(index)"
    case let .both(str, _): return str
    }
  }

  var intValue: Int? {
    switch representation {
    case .string: return nil
    case let .int(int): return int
    case let .index(index): return index
    case let .both(_, int): return int
    }
  }
}
