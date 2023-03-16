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
import NIOCore
import NIONetbot

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
open class ProfileSerialization {

    struct JSONKey: Equatable, RawRepresentable {

        static let general: JSONKey = .init(rawValue: "general")!
        static let replica: JSONKey = .init(rawValue: "replica")!
        static let policies: JSONKey = .init(rawValue: "policies")!
        static let policyGroups: JSONKey = .init(rawValue: "policy_groups")!
        static let rules: JSONKey = .init(rawValue: "rules")!
        static let mitm: JSONKey = .init(rawValue: "mitm")!

        typealias RawValue = String

        var rawValue: RawValue

        init?(rawValue: RawValue) {
            switch rawValue {
                case "[General]":
                    self.rawValue = "general"
                case "[Policies]":
                    self.rawValue = "policies"
                case "[Policy Group]":
                    self.rawValue = "policy_groups"
                case "[Rule]":
                    self.rawValue = "rules"
                case "[MitM]":
                    self.rawValue = "mitm"
                default:
                    // Convert kebab case to snake case
                    self.rawValue = rawValue.replacingOccurrences(of: "-", with: "_")
            }
        }
    }

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
                case "dns_servers", "exceptions", "hostnames":
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
    open class func jsonObject(with data: ByteBuffer) throws -> Any {
        var __rulesKeyedByLine: [Int: String] = [:]
        var __groupKeyedByLine: [Int: [String: [String]]] = [:]
        var __policies: [String] = Builtin.policies.map { $0.name }

        /// Line number being parsed.
        var cursor: Int = 0

        var json: JSONValue = .object([:])
        var parser = ProfileParser.init(byteBuffer: data)

        var currentGroup: JSONKey?

        try parser.parse().forEach { next in
            cursor += 1

            guard case .object(var _json) = json else {
                preconditionFailure()
            }

            switch (next, currentGroup) {
                case (.comment, _), (.blank, _):
                    return

                case (.section(let g), _):
                    currentGroup = .init(rawValue: g)

                case (.string(let l), _):
                    if currentGroup == .rules {
                        __rulesKeyedByLine[cursor] = l
                    }

                    guard let currentGroup = currentGroup else {
                        throw ProfileSerializationError.dataCorrupted
                    }

                    guard case .array(var array) = _json[currentGroup.rawValue] ?? .array([]) else {
                        preconditionFailure()
                    }

                    array.append(.convertFromString(l))

                    _json[currentGroup.rawValue] = .array(array)

                    json = .object(_json)

                case (.object(let o), .some(.policies)):
                    guard let currentGroup = currentGroup else {
                        throw ProfileSerializationError.dataCorrupted
                    }

                    guard case .array(var array) = _json[currentGroup.rawValue] ?? .array([]) else {
                        preconditionFailure()
                    }

                    __policies.append(o.0)

                    // Rebuild policies as json array.
                    let components = o.1.split(separator: ",")

                    var configuration: [String: JSONValue] = [:]
                    components.suffix(from: 1)
                        .forEach {
                            let components = $0.split(separator: "=").map {
                                $0.trimmingCharacters(in: .whitespaces)
                            }
                            let jsonKey = JSONKey(rawValue: components.first!)!.rawValue
                            configuration[jsonKey] = .convertFromString(
                                components.last!,
                                forKey: jsonKey
                            )
                        }

                    let `protocol` = JSONValue.string(
                        components[0].trimmingCharacters(in: .whitespaces)
                    )
                    configuration["protocol"] = `protocol`

                    let jsonValue = JSONValue.object([
                        __Policy.CodingKeys.name.rawValue: .string(o.0),
                        __Policy.CodingKeys.type.rawValue: `protocol`,
                        __Policy.CodingKeys.proxy.rawValue: .object(configuration),
                    ])

                    array.append(jsonValue)

                    _json[currentGroup.rawValue] = .array(array)

                    json = .object(_json)

                case (.object(let o), .some(.policyGroups)):
                    guard let currentGroup = currentGroup else {
                        throw ProfileSerializationError.dataCorrupted
                    }
                    //
                    guard case .array(var array) = _json[currentGroup.rawValue] ?? .array([]) else {
                        preconditionFailure()
                    }

                    // Rebuild policy group as json array.
                    let policies = o.1
                        .split(separator: ",")
                        .map { $0.trimmingCharacters(in: .whitespaces) }

                    __groupKeyedByLine[cursor] = [o.0: policies]

                    let jsonValue = JSONValue.object([
                        PolicyGroup.CodingKeys.name.rawValue: .string(o.0),
                        PolicyGroup.CodingKeys.policies.rawValue: .array(
                            policies.map(JSONValue.string)
                        ),
                    ])

                    array.append(jsonValue)

                    _json[currentGroup.rawValue] = .array(array)

                    json = .object(_json)

                case (.object(let o), _):
                    guard let currentGroup = currentGroup else {
                        preconditionFailure()
                    }

                    guard
                        case .object(var dictionary) = _json[currentGroup.rawValue] ?? .object([:])
                    else {
                        preconditionFailure()
                    }

                    let jsonKey = JSONKey(rawValue: o.0)!.rawValue

                    dictionary[jsonKey] = .convertFromString(o.1, forKey: jsonKey)

                    _json[currentGroup.rawValue] = .object(dictionary)

                    json = .object(_json)
            }
        }

        // File validating.
        // All proxy used in policy group must declare in [Proxy Policy].
        try __groupKeyedByLine.forEach { (cursor, line) in
            try line.values.joined().forEach { name in
                guard __policies.contains(where: { $0 == name }) else {
                    throw ProfileSerializationError.invalidFile(
                        reason: .unknownPolicy(cursor: cursor, policy: name)
                    )
                }
            }
        }

        // All proxy label defined in rule should
        try __rulesKeyedByLine.forEach { (cursor, line) in
            let rawValue = line.split(separator: ",").first!.trimmingCharacters(in: .whitespaces)
            guard let factory = RuleSystem.factory(for: .init(rawValue: rawValue)),
                let rule = factory.init(line)
            else {
                throw ProfileSerializationError.invalidFile(
                    reason: .invalidLine(cursor: cursor, description: line)
                )
            }
            // Validate rule policy.
            let all =
                __policies
                + Array(
                    __groupKeyedByLine.values.reduce(
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
    open class func jsonObject(with data: Data) throws -> Any {
        try jsonObject(with: ByteBuffer.init(bytes: data))
    }

    /// Generate Profile data from a Foundation object. If the object will not produce valid JSON
    /// then an exception will be thrown.
    /// - Parameter obj: Foundation NSDictionary object.
    /// - Returns: Generated configuration file data.
    open class func data(withJSONObject obj: Any) throws -> Data {
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

            switch key {
                case JSONKey.general.rawValue:
                    components.append("[General]")
                case JSONKey.policies.rawValue:
                    components.append("[Policies]")
                case JSONKey.policyGroups.rawValue:
                    components.append("[Policy Group]")
                case JSONKey.rules.rawValue:
                    components.append("[Rule]")
                case JSONKey.mitm.rawValue:
                    components.append("[MitM]")
                default:
                    components.append("\(key)")
            }

            guard key != JSONKey.policyGroups.rawValue else {
                guard let selectablePolicyGroups = value as? [[String: Any]] else {
                    throw ProfileSerializationError.dataCorrupted
                }
                selectablePolicyGroups.forEach {
                    let policies = ($0[JSONKey.policies.rawValue] as? [String]) ?? []
                    components.append("\($0["name"]!) = \(policies.joined(separator: ","))")
                }
                return
            }

            guard key != JSONKey.policies.rawValue else {
                guard let policies = value as? [[String: Any]] else {
                    throw ProfileSerializationError.dataCorrupted
                }

                components.append(
                    contentsOf: try policies.map {
                        guard
                            let configuration = $0[__Policy.CodingKeys.proxy.rawValue]
                                as? [String: Any],
                            let name = $0[__Policy.CodingKeys.name.rawValue],
                            let type = $0[__Policy.CodingKeys.type.rawValue]
                        else {
                            throw ProfileSerializationError.dataCorrupted
                        }

                        let configurationString = configuration.map {
                            "\($0.key.replacingOccurrences(of: "_", with: "-"))=\($0.value)"
                        }.joined(separator: ", ")

                        return "\(name) = \(type), \(configurationString)"
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
                    let v = dictionary[k]!

                    let k = k.replacingOccurrences(of: "_", with: "-")
                    if k == "exceptions" || k == "dns-servers" || k == "hostnames" {
                        guard let l = v as? [String] else {
                            throw ProfileSerializationError.dataCorrupted
                        }
                        components.append("\(k) = \(l.joined(separator: ","))")
                    } else {
                        components.append("\(k) = \(v)")
                    }
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

extension ProfileSerialization.JSONValue {

    fileprivate func toObjcRepresentation() throws -> Any {
        switch self {
            case .array(let values):
                return try values.map { try $0.toObjcRepresentation() }
            case .object(let object):
                return try object.mapValues { try $0.toObjcRepresentation() }
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
