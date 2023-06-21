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

import Foundation
@_exported import NIOCore

/// Errors that can be raised while parsing profile file.
public enum ProfileSerializationError: Error {

  /// Error reason for invalid file
  public enum InvalidFileErrorReason: CustomStringConvertible, Sendable {

    /// Line is invalid at cursor line
    case invalidLine(cursor: Int, description: String)

    /// Data represent for this configuration file is corrupted.
    case dataCorrupted

    /// Unknown policy define at cursor line.
    case unknownPolicy(cursor: Int, policy: String)

    public var description: String {
      switch self {
      case .invalidLine(let cursor, let description):
        return "invalid line #\(cursor): \(description)."
      case .unknownPolicy(let cursor, let policy):
        return "invalid line #\(cursor): include an unknown policy \"\(policy)\"."
      case .dataCorrupted:
        return "data corrupted."
      }
    }
  }

  /// Error reason for invalid rule.
  public enum RuleParsingErrorReason: CustomStringConvertible, Sendable {

    /// Rule missing field.
    case missingField

    /// Unsupported rule.
    case unsupported

    /// Exteranl resources url is invalid.
    case invalidExternalResources

    /// Error that failed to parse rule to specified type.
    case failedToParseAs(ParsableRule.Type, butCanBeParsedAs: ParsableRule.Type)

    public var description: String {
      switch self {
      case .missingField:
        return "missing field."
      case .unsupported:
        return "unsupported rule type."
      case .invalidExternalResources:
        return "invalid external resources."
      case .failedToParseAs(let expected, butCanBeParsedAs: let actual):
        return "failed to parse as \(expected), but can be parsed as \(actual)."
      }
    }
  }

  /// Error with invalid file error reason `InvalidFileErrorReason`.
  case invalidFile(reason: InvalidFileErrorReason)

  /// Failed to parse rule with specified error reason `RuleParsingErrorReason`.
  case failedToParseRule(reason: RuleParsingErrorReason)

  /// Error that data corrupted.
  case dataCorrupted
}

/// An object that converts between configuration file and the equivalent Foundation objects.
///
/// You use the JSONSerialization class to convert JSON to Foundation objects and convert Foundation
/// objects to JSON.
/// To convert a json object to data the object must is a NSDIctionary with String keys.
final public class ProfileSerialization {

  enum JSONValue: Equatable {
    case string(String)
    case number(String)
    case bool(Bool)
    case null

    case array([JSONValue])
    case object([String: JSONValue])

    static func convertFromString(_ string: String) -> JSONValue {
      switch string {
      case "true":
        return .bool(true)
      case "false":
        return .bool(false)
      default:
        return .string(string)
      }
    }

    static func convertFromString(_ string: String, forKey key: String) -> JSONValue {
      switch key {
      case "dns-servers", "exceptions", "hostnames":
        return .array(
          string.split(separator: ",")
            .map { .convertFromString($0.trimmingCharacters(in: .whitespaces)) }
        )
      case _ where key.hasSuffix("port"):
        return .number(string)
      default:
        return .convertFromString(string)
      }
    }
  }

  /// Create a Foundation object from configuration file data.
  /// - Parameter data: The configuration file byte buffer.
  /// - Returns: Foundation NSDictionary object.
  public class func jsonObject(with data: ByteBuffer) throws -> Any {
    var _rulesKeyedByLine: [Int: String] = [:]
    var _groupKeyedByLine: [Int: [String: [String]]] = [:]
    var _policies: [String] = []

    /// Line number being parsed.
    var cursor: Int = 0

    var json: JSONValue = .object([:])
    var parser = ProfileParser.init(byteBuffer: data)

    var currentGroup: String?

    try parser.parse().forEach { next in
      cursor += 1

      guard case .object(var _json) = json else {
        throw ProfileSerializationError.dataCorrupted
      }

      switch next {
      // Ignore comment and black line.
      case .comment, .blank:
        return

      case .section(let g):
        currentGroup = g

      case .string(let l):
        guard let currentGroup, case .array(var array) = _json[currentGroup] ?? .array([]) else {
          throw ProfileSerializationError.dataCorrupted
        }
        if currentGroup == "[Rule]" {
          _rulesKeyedByLine[cursor] = l
        }
        array.append(.convertFromString(l))
        _json[currentGroup] = .array(array)
        json = .object(_json)

      case .object(let o):
        guard let currentGroup else {
          throw ProfileSerializationError.dataCorrupted
        }

        var jsonValue: JSONValue

        switch currentGroup {
        case "[Policies]":
          if ["DIRECT", "REJECT", "REJECT-TINYGIF"].contains(o.0) && o.0.lowercased() != o.1 {
            throw ProfileSerializationError.invalidFile(
              reason: .invalidLine(
                cursor: cursor,
                description:
                  "\(o.0) is used as builtin policy types, consider use another name instead."
              )
            )
          }
          // Policies should serialized to json array.
          guard case .array(var array) = _json[currentGroup] ?? .array([]) else {
            throw ProfileSerializationError.dataCorrupted
          }
          _policies.append(o.0)
          array.append(try serializePolicy(o))
          jsonValue = .array(array)

        case "[Policy Group]":
          // Policy gorup should serialized to json array.
          guard case .array(var array) = _json[currentGroup] ?? .array([]) else {
            throw ProfileSerializationError.dataCorrupted
          }

          guard case .object(let j) = try serializePolicyGroup(o),
            case .array(let policies) = j[AnyPolicyGroup.CodingKeys.policies.rawValue]
          else {
            throw ProfileSerializationError.dataCorrupted
          }
          _groupKeyedByLine[cursor] = [
            o.0: policies.compactMap({
              guard case .string(let p) = $0 else {
                return nil
              }
              return p
            })
          ]
          array.append(try serializePolicyGroup(o))
          jsonValue = .array(array)
        default:
          guard case .object(var dictionary) = _json[currentGroup] ?? .object([:]) else {
            throw ProfileSerializationError.dataCorrupted
          }
          dictionary[o.0] = .convertFromString(o.1, forKey: o.0)
          jsonValue = .object(dictionary)
        }

        _json[currentGroup] = jsonValue
        json = .object(_json)
      }
    }

    // Add missing builtin policies
    if !_policies.contains("REJECT-TINYGIF") {
      _policies.append("REJECT-TINYGIF")
    }
    if !_policies.contains("REJECT") {
      _policies.append("REJECT")
    }
    if !_policies.contains("DIRECT") {
      _policies.append("DIRECT")
    }

    // File validating.
    // All proxy used in policy group must declare in [Proxy Policy].
    try _groupKeyedByLine.forEach { (cursor, line) in
      try line.values.joined().forEach { name in
        guard _policies.contains(where: { $0 == name }) else {
          throw ProfileSerializationError.invalidFile(
            reason: .unknownPolicy(cursor: cursor, policy: name)
          )
        }
      }
    }

    try _rulesKeyedByLine.forEach { (cursor, line) in
      let rawValue = line.split(separator: ",").first?.trimmingCharacters(in: .whitespaces) ?? ""
      guard let factory = RuleSystem.factory(for: .init(rawValue: rawValue)),
        let rule = factory.init(line)
      else {
        throw ProfileSerializationError.invalidFile(
          reason: .invalidLine(cursor: cursor, description: line)
        )
      }
      // Rule.policy should be the name of one of policies and policyGroups
      let all =
        _policies
        + Array(
          _groupKeyedByLine.values.reduce(
            into: [],
            { partialResult, next in
              partialResult.append(contentsOf: next.keys)
              partialResult.append(contentsOf: next.values.joined())
            }
          )
        )

      guard all.contains(where: { $0 == rule.policy }) else {
        throw ProfileSerializationError.invalidFile(
          reason: .unknownPolicy(cursor: cursor, policy: rule.policy)
        )
      }
    }

    return try json.toObjcRepresentation()
  }

  /// Create a Foundation object from configuration file data.
  /// - Parameter data: The configuration file data.
  /// - Returns: Foundation NSDictionary object.
  public class func jsonObject(with data: Data) throws -> Any {
    try jsonObject(with: ByteBuffer.init(bytes: data))
  }

  /// Generate Profile data from a Foundation object. If the object will not produce valid JSON
  /// then an exception will be thrown.
  /// - Parameter obj: Foundation NSDictionary object.
  /// - Returns: Generated configuration file data.
  public class func data(withJSONObject obj: Any) throws -> Data {
    guard let json = obj as? [String: Any] else {
      throw ProfileSerializationError.dataCorrupted
    }

    var components: [String] = []
    let newLine = "\n"

    try json.keys.sorted().forEach { key in
      let value = json[key]

      defer {
        components.append(newLine)
      }

      components.append(key.convertToKebabCase())

      guard key != Profile.CodingKeys.policyGroups.rawValue else {
        guard let g = value as? [[String: Any]] else {
          throw ProfileSerializationError.dataCorrupted
        }
        components.append(
          contentsOf: try g.map {
            guard let name = $0[AnyPolicyGroup.CodingKeys.name.rawValue] as? String else {
              throw ProfileSerializationError.dataCorrupted
            }
            guard let policies = $0[AnyPolicyGroup.CodingKeys.policies.rawValue] as? [String] else {
              return "\(name) = "
            }
            return
              "\(name) = \($0[AnyPolicyGroup.CodingKeys.type.rawValue] ?? "select"), policies = \(policies.joined(separator: ", "))"
          }
        )
        return
      }

      guard key != Profile.CodingKeys.policies.rawValue else {
        guard let policies = value as? [[String: Any]] else {
          throw ProfileSerializationError.dataCorrupted
        }

        components.append(
          contentsOf: try policies.map {
            // Only proxy policy requires proxy configurations
            let proxy = $0[AnyConnectionPolicy.CodingKeys.proxy.rawValue] as? [String: Any]
            guard let name = $0[AnyConnectionPolicy.CodingKeys.name.rawValue],
              let type = $0[AnyConnectionPolicy.CodingKeys.type.rawValue]
            else {
              throw ProfileSerializationError.dataCorrupted
            }

            let configurationString = try proxy?.sorted(by: { lhs, rhs in
              lhs.key < rhs.key
            }).map {
              "\($0.key.convertToKebabCase()) = \(try serialize($0.value))"
            }.joined(separator: ", ")

            if let configurationString {
              return "\(name) = \(type), \(configurationString)"
            } else {
              return "\(name) = \(type)"
            }
          }
        )
        return
      }

      if let array = value as? [Any] {
        array.forEach {
          components.append("\($0)")
        }
      } else if let dictionary = value as? [String: Any] {
        try dictionary.keys.sorted().forEach { k in
          guard let v = dictionary[k] else {
            fatalError("This should never happen!!")
          }
          let k = k.convertToKebabCase()
          components.append("\(k) = \(try serialize(v))")
        }
      } else {
        throw ProfileSerializationError.dataCorrupted
      }
    }

    return components.dropLast()
      .joined(separator: newLine)
      .replacingOccurrences(of: newLine + newLine, with: newLine)
      .data(using: .utf8) ?? .init()
  }
}

extension ProfileSerialization {

  private static func serializePolicy(_ o: (String, String)) throws -> JSONValue {
    // direct reject and reject-tinygif does not requires extra configurations
    if ["direct", "reject", "reject-tinygif"].contains(o.1) {
      return .object([
        AnyConnectionPolicy.CodingKeys.name.rawValue: .string(o.0),
        AnyConnectionPolicy.CodingKeys.type.rawValue: .string(o.1),
      ])
    } else {
      // Rebuild proxy configuration as json array.
      let components = o.1.split(separator: ",")

      var configuration: [String: JSONValue] = [:]

      // First component should be policy type, and proxy configuration should stay after type.
      components.suffix(from: 1)
        .forEach {
          let substrings = $0.split(
            separator: "=",
            omittingEmptySubsequences: false
          ).map { $0.trimmingCharacters(in: .whitespaces) }

          let jsonKey = substrings.first ?? ""

          configuration[jsonKey] = .convertFromString(
            substrings.last ?? "",
            forKey: jsonKey
          )
        }

      let `protocol` = JSONValue.string(
        components[0].trimmingCharacters(in: .whitespaces)
      )
      configuration["protocol"] = `protocol`

      return .object([
        AnyConnectionPolicy.CodingKeys.name.rawValue: .string(o.0),
        AnyConnectionPolicy.CodingKeys.type.rawValue: `protocol`,
        AnyConnectionPolicy.CodingKeys.proxy.rawValue: .object(configuration),
      ])
    }
  }

  private static func serializePolicyGroup(_ o: (String, String)) throws -> JSONValue {
    // Rebuild proxy configuration as json array.
    let name = o.0.trimmingWhitespaces()
    var expression = o.1

    guard let maxLength = expression.firstIndex(of: ",") else {
      throw ProfileSerializationError.dataCorrupted
    }

    var startIndex = expression.startIndex
    let type = expression[startIndex..<maxLength].trimmingWhitespaces()

    // Remove type
    startIndex = expression.index(after: maxLength)
    expression = expression[startIndex...].trimmingWhitespaces()

    var components = expression.split(separator: "=")

    var json = JSONValue.object([:])

    while !components.isEmpty {
      let key = components.removeFirst()
      var values = components.removeFirst().split(separator: ",")
      if !components.isEmpty {
        components.insert(values.removeLast(), at: 0)
      }
      guard case .object(var j) = json else {
        fatalError()
      }
      j[key.trimmingWhitespaces()] = .array(values.map({ .string($0.trimmingWhitespaces()) }))
      json = .object(j)
    }

    guard case .object(var j) = json else {
      fatalError()
    }
    j[AnyPolicyGroup.CodingKeys.name.rawValue] = .string(name)
    j[AnyPolicyGroup.CodingKeys.type.rawValue] = .string(type)
    return .object(j)
  }

  private static func serialize(_ obj: Any) throws -> String {
    // For better performance, the most expensive conditions to evaluate should be last.
    switch obj {
    case let str as String:
      return str
    case let boolValue as Bool:
      return boolValue.description
    case let num as Int:
      return num.description
    case let num as Int8:
      return num.description
    case let num as Int16:
      return num.description
    case let num as Int32:
      return num.description
    case let num as Int64:
      return num.description
    case let num as UInt:
      return num.description
    case let num as UInt8:
      return num.description
    case let num as UInt16:
      return num.description
    case let num as UInt32:
      return num.description
    case let num as UInt64:
      return num.description
    case let array as [Any?]:
      return try array.compactMap {
        guard let obj = $0 else {
          return nil
        }
        return try serialize(obj)
      }.joined(separator: ", ")
    case let dict as [AnyHashable: Any?]:
      guard let obj = dict as? [String: Any?] else {
        throw NSError(
          domain: NSCocoaErrorDomain,
          code: CocoaError.propertyListReadCorrupt.rawValue,
          userInfo: [NSDebugDescriptionErrorKey: "NSDictionary key must be NSString"]
        )
      }
      return try obj.keys.sorted().map {
        guard let v = obj[$0], let v else {
          return "\($0) = "
        }
        return "\($0) = \(try serialize(v))"
      }.joined(separator: ",")
    case let num as Float:
      return num.description
    case let num as Double:
      return num.description
    case let num as Decimal:
      return num.description
    case let num as NSDecimalNumber:
      return num.description
    case is NSNull:
      return "null"
    case let num as NSNumber:
      return num.description
    default:
      throw NSError(
        domain: NSCocoaErrorDomain,
        code: CocoaError.propertyListReadCorrupt.rawValue,
        userInfo: [NSDebugDescriptionErrorKey: "Invalid object cannot be serialized"]
      )
    }
  }
}

extension ProfileSerialization.JSONValue {

  fileprivate func toObjcRepresentation() throws -> Any {
    switch self {
    case .array(let values):
      return try values.map { try $0.toObjcRepresentation() }
    case .object(let object):
      var converted: [String: Any] = [:]
      try object.forEach {
        converted[$0.key.convertToCamelCase()] = try $0.value.toObjcRepresentation()
      }
      return converted
    case .bool(let bool):
      return bool
    case .number(let string):
      return NSNumber.fromJSONNumber(string) ?? NSNumber(value: 0)
    case .null:
      return NSNull()
    case .string(let string):
      return string
    }
  }
}

extension NSNumber {

  fileprivate static func fromJSONNumber(_ string: String) -> NSNumber? {
    let decIndex = string.firstIndex(of: ".")
    let expIndex = string.firstIndex(of: "e")
    let isInteger = decIndex == nil && expIndex == nil
    let isNegative = string.utf8[string.utf8.startIndex] == UInt8(ascii: "-")
    let digitCount = string[string.startIndex..<(expIndex ?? string.endIndex)].count

    // Try Int64() or UInt64() first
    if isInteger {
      if isNegative {
        if digitCount <= 19, let intValue = Int64(string) {
          return NSNumber(value: intValue)
        }
      } else {
        if digitCount <= 20, let uintValue = UInt64(string) {
          return NSNumber(value: uintValue)
        }
      }
    }

    var exp = 0

    if let expIndex = expIndex {
      let expStartIndex = string.index(after: expIndex)
      if let parsed = Int(string[expStartIndex...]) {
        exp = parsed
      }
    }

    // Decimal holds more digits of precision but a smaller exponent than Double
    // so try that if the exponent fits and there are more digits than Double can hold
    if digitCount > 17, exp >= -128, exp <= 127, let decimal = Decimal(string: string),
      decimal.isFinite
    {
      return NSDecimalNumber(decimal: decimal)
    }

    // Fall back to Double() for everything else
    if let doubleValue = Double(string), doubleValue.isFinite {
      return NSNumber(value: doubleValue)
    }

    return nil
  }
}

extension String {

  func convertToCamelCase() -> String {
    switch self {
    case "[General]": return "basicSettings"
    case "[Rule]": return "rules"
    case "[Policies]": return "policies"
    case "[Policy Group]": return "policyGroups"
    case "[MitM]": return "manInTheMiddleSettings"
    default:
      let stringKey = self
      guard !stringKey.isEmpty else { return stringKey }

      // Find the first non-underscore character
      guard let firstNonUnderscore = stringKey.firstIndex(where: { $0 != "-" }) else {
        // Reached the end without finding an _
        return stringKey
      }

      // Find the last non-underscore character
      var lastNonUnderscore = stringKey.index(before: stringKey.endIndex)
      while lastNonUnderscore > firstNonUnderscore && stringKey[lastNonUnderscore] == "-" {
        stringKey.formIndex(before: &lastNonUnderscore)
      }

      let keyRange = firstNonUnderscore...lastNonUnderscore
      let leadingUnderscoreRange = stringKey.startIndex..<firstNonUnderscore
      let trailingUnderscoreRange =
        stringKey.index(after: lastNonUnderscore)..<stringKey.endIndex

      let components = stringKey[keyRange].split(separator: "-")
      let joinedString: String
      if components.count == 1 {
        // No underscores in key, leave the word as is - maybe already camel cased
        joinedString = String(stringKey[keyRange])
      } else {
        joinedString =
          ([components[0].lowercased()] + components[1...].map { $0.capitalized })
          .joined()
      }

      // Do a cheap isEmpty check before creating and appending potentially empty strings
      let result: String
      if leadingUnderscoreRange.isEmpty && trailingUnderscoreRange.isEmpty {
        result = joinedString
      } else if !leadingUnderscoreRange.isEmpty && !trailingUnderscoreRange.isEmpty {
        // Both leading and trailing underscores
        result =
          String(stringKey[leadingUnderscoreRange]) + joinedString
          + String(stringKey[trailingUnderscoreRange])
      } else if !leadingUnderscoreRange.isEmpty {
        // Just leading
        result = String(stringKey[leadingUnderscoreRange]) + joinedString
      } else {
        // Just trailing
        result = joinedString + String(stringKey[trailingUnderscoreRange])
      }
      return result
    }
  }

  func convertToKebabCase() -> String {
    switch self {
    case "basicSettings": return "[General]"
    case "rules": return "[Rule]"
    case "policies": return "[Policies]"
    case "policyGroups": return "[Policy Group]"
    case "manInTheMiddleSettings": return "[MitM]"
    default:
      let stringKey = self
      guard !stringKey.isEmpty else { return stringKey }

      return (stringKey.first?.lowercased() ?? "")
        + stringKey.dropFirst().map {
          $0.isUppercase ? "-\($0.lowercased())" : "\($0)"
        }.joined()
    }
  }
}
