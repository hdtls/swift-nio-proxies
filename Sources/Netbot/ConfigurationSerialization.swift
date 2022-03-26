//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2021 Junfeng Zhang. and the Netbot project authors
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

/// Errors that can be raised while parsing configuration file.
public enum ConfigurationSerializationError: Error {
    
    /// Error reason for invalid file
    public enum InvalidFileErrorReason: CustomStringConvertible {
        
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
    public enum RuleParsingErrorReason: CustomStringConvertible {
        
        /// Rule missing field.
        case missingField
        
        /// Unsupported rule.
        case unsupported
        
        /// Exteranl resources url is invalid.
        case invalidExternalResources
        
        /// Error that failed to parse rule to specified type.
        case failedToParseAs(Rule.Type, butCanBeParsedAs: Rule.Type)
        
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
final public class ConfigurationSerialization {
    
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
                case "[Replica]":
                    self.rawValue = "replica"
                case "[Proxy Policy]":
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
    
    /// Create a Foundation object from configuration file data.
    /// - Parameter data: The configuration file byte buffer.
    /// - Returns: Foundation NSDictionary object.
    public static func jsonObject(with data: ByteBuffer) throws -> Any {
        var ruleLineMap: [Int : DocumentParser.Line] = [:]
        var policyGroupMap: [Int : DocumentParser.Line] = [:]
        var proxyMap: [Int : DocumentParser.Line] = [:]
        let builtin: [DocumentParser.Line] = Builtin.policies.map {
            DocumentParser.Line(key: .init(rawValue: $0.name)!, value: "")
        }
                
        /// Line number being parsed.
        var cursor: Int = 0
        
        
        var json: [String : Any] = [:]
        var parser = DocumentParser.init(byteBuffer: data)
        
        var currentGroup: JSONKey?
        
        try parser.parse().forEach { next in
            cursor += 1
            
            // Comment and empty line will be ignored.
            guard next.key != .commentLine, next.key != .newLine else {
                return
            }
            
            guard next.key != .mdlLine else {
                currentGroup = .init(rawValue: next.value)
                return
            }
            
            guard let currentGroup = currentGroup else {
                throw ConfigurationSerializationError.dataCorrupted
            }
            
            let actual = tryAsBool(next.value)
            
            // Rebuild policy group as json array.
            guard currentGroup != .policyGroups else {
                var array: [Any] = (json[currentGroup.rawValue] as? [Any]) ?? []
                // TODO: Hard Code
                let _json: [String : Any] = [
                    "name" : next.key.rawValue,
                    JSONKey.policies.rawValue : next.value.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                ]
                array.append(_json)
                json[currentGroup.rawValue] = array

                policyGroupMap[cursor] = next
                return
            }
            
            // Rebuild policies as json array.
            guard currentGroup != .policies else {
                var array: [Any] = (json[currentGroup.rawValue] as? [Any]) ?? []
                array.append("\(JSONKey(rawValue: next.key.rawValue)!.rawValue)=\(next.value)")
                json[currentGroup.rawValue] = array
                
                proxyMap[cursor] = next
                return
            }
            
            if currentGroup == .rules {
                ruleLineMap[cursor] = next
            }
            
            if next.key == .elementLine {
                var array: [Any] = (json[currentGroup.rawValue] as? [Any]) ?? []
                array.append(actual)
                json[currentGroup.rawValue] = array
            } else {
                var _json = (json[currentGroup.rawValue] as? [String : Any]) ?? [:]
                let key = JSONKey(rawValue: next.key.rawValue)!.rawValue
                // TODO: Hard Code
                if key == "dns_servers" || key == "exceptions" || key == "hostnames" {
                    _json[key] = next.value.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                } else {
                    _json[key] = key.hasSuffix("_port") ? Int(next.value) as Any : actual
                }
                json[currentGroup.rawValue] = _json
            }
        }
        
        
        // File validating.
        // All proxy used in policy group must declare in [Proxy Policy].
        try policyGroupMap.forEach { (cursor, line) in
            try line.value
                .split(separator: ",")
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .forEach { name in
                    let all = Array(proxyMap.values) + builtin
                    
                    guard name == "select" || all.contains(where: { $0.key.rawValue == name }) else {
                        throw ConfigurationSerializationError.invalidFile(reason: .unknownPolicy(cursor: cursor, policy: name))
                    }
                }
        }
        
        // All proxy label defined in rule should
        try ruleLineMap.forEach { (cursor, line) in
            guard let rule = try? AnyRule.init(stringLiteral: line.value) else {
                throw ConfigurationSerializationError.invalidFile(reason: .invalidLine(cursor: cursor, description: line.value))
            }
            // Validate rule policy.
            let all = Array(proxyMap.values) + Array(policyGroupMap.values) + builtin
            
            guard all.contains(where: { $0.key.rawValue == rule.policy }) else {
                throw ConfigurationSerializationError.invalidFile(reason: .unknownPolicy(cursor: cursor, policy: rule.policy))
            }
        }
        
        return json
    }
    
    private static func tryAsBool(_ value: String) -> Any {
        switch value {
            case "true":
                return true
            case "false":
                return false
            default:
                return value
        }
    }
    
    /// Create a Foundation object from configuration file data.
    /// - Parameter data: The configuration file data.
    /// - Returns: Foundation NSDictionary object.
    public static func jsonObject(with data: Data) throws -> Any {
        try jsonObject(with: ByteBuffer.init(bytes: data))
    }
    
    /// Generate Configuration data from a Foundation object. If the object will not produce valid JSON
    /// then an exception will be thrown.
    /// - Parameter obj: Foundation NSDictionary object.
    /// - Returns: Generated configuration file data.
    public static func data(withJSONObject obj: Any) throws -> Data {
        guard let json = obj as? [String : Any] else {
            throw ConfigurationSerializationError.dataCorrupted
        }
        
        var stringLiteral = ""
        
        json.keys.sorted().forEach { key in
            let value = json[key]
            
            if !stringLiteral.isEmpty {
                stringLiteral.append("\n")
            }
            
            switch key {
                case JSONKey.general.rawValue:
                    stringLiteral.append("[General]\n")
                case JSONKey.replica.rawValue:
                    stringLiteral.append("[Replica]\n")
                case JSONKey.policies.rawValue:
                    stringLiteral.append("[Proxy Policy]\n")
                case JSONKey.policyGroups.rawValue:
                    stringLiteral.append("[Policy Group]\n")
                case JSONKey.rules.rawValue:
                    stringLiteral.append("[Rule]\n")
                case JSONKey.mitm.rawValue:
                    stringLiteral.append("[MitM]\n")
                default:
                    stringLiteral.append("\(key)\n")
            }
            
            guard key != JSONKey.policyGroups.rawValue else {
                guard let selectablePolicyGroups = value as? [[String : Any]] else {
                    return
                }
                selectablePolicyGroups.forEach {
                    let policies = ($0[JSONKey.policies.rawValue] as? [String]) ?? []
                    stringLiteral.append("\($0["name"]!) = \(policies.joined(separator: ","))\n")
                }
                return
            }
            
            if let array = value as? [Any?] {
                array.forEach {
                    if let v = $0 {
                        stringLiteral.append("\(v)\n")
                    }
                }
            } else if let dictionary = value as? Dictionary<String, Any> {
                dictionary.keys.sorted().forEach {
                    let k = $0.replacingOccurrences(of: "_", with: "-")
                    
                    if $0 == "exceptions" || $0 == "dns_servers" || $0 == "hostnames" {
                        let l = dictionary[$0] as? [String] ?? []
                        stringLiteral.append("\(k) = \(l.joined(separator: ","))\n")
                    } else {
                        if let v = dictionary[$0] {
                            stringLiteral.append("\(k) = \(v)\n")
                        }
                    }
                }
            }
        }
        
        return stringLiteral.data(using: .utf8) ?? .init()
    }
    
    static func write(_ json: Any?, dst: inout String) {
        if let v = json {
            dst.append("\(v)")
        }
    }
}
