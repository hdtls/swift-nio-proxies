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
import NIO
import NIOPosix

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
    public enum InvalidRuleErrorReason: CustomStringConvertible {
        
        /// Rule missing field.
        case missingField
        
        /// Unsupported rule.
        case unsupported
        
        public var description: String {
            switch self {
                case .missingField:
                    return "missing field."
                case .unsupported:
                    return "unsupported rule type."
            }
        }
    }
    
    /// Error with invalid file error reason `InvalidFileErrorReason`.
    case invalidFile(reason: InvalidFileErrorReason)
    
    /// Error with invalid rule error reason `InvalidRuleErrorReason`.
    case invalidRule(reason: InvalidRuleErrorReason)
    
    /// Error that failed to parse rule to specified type.
    case failedToParseAs(Rule.Type, butCanBeParsedAs: Rule.Type)
    
    /// Error that data corrupted.
    case dataCorrupted
}

/// An object that converts between configuration file and the equivalent Foundation objects.
///
/// You use the JSONSerialization class to convert JSON to Foundation objects and convert Foundation
/// objects to JSON.
/// To convert a json object to data the object must is a NSDIctionary with String keys.
final public class ConfigurationSerialization {

    private enum Cursor: String {
        case mdlLine = "cursor.__MODULE_LINE"
        case commentLine = "cursor.__COMMENT_LINE"
        case newLine = "cursor.__NEW_LINE"
        case markableLine = "cursor.__MARKABLE_LINE"
    }
    
    /// Represents a `KEY=VALUE` pair in a dotenv file.
    struct Line: Equatable {
        /// The key.
        let key: String
        
        /// The value.
        let value: String
    }
    
    private var source: ByteBuffer
    
    private var currentGroup: String = ""
    
    private var previous: UInt8?
    
    /// Line number being parsed.
    private var cursor: Int = 0
    
    /// A boolean value that determines whether to convert string to bool if possible.
    public static var converStringToBoolIfPossible: Bool = true
    
    private init(source: ByteBuffer) {
        self.source = source
    }
    
    /// Create a Foundation object from configuration file data.
    /// - Parameter data: The configuration file byte buffer.
    /// - Returns: Foundation NSDictionary object.
    public static func jsonObject(with data: ByteBuffer) throws -> Any {
        var json: [String : Any] = [:]
        let parser = ConfigurationSerialization.init(source: data)
        
        try parser.parse().forEach { next in
            // Comment and empty line will be ignored.
            guard next.key != Cursor.commentLine.rawValue, next.key != Cursor.newLine.rawValue else {
                return
            }
            
            guard next.key != Cursor.mdlLine.rawValue else {
                parser.currentGroup = next.value.trimmingCharacters(in: .whitespaces)
                return
            }
            
            var actual: Any
            let value = next.value.trimmingCharacters(in: .whitespaces)
            // Convert String to Bool if possible.
            if Self.converStringToBoolIfPossible {
                switch value {
                    case "true":
                        actual = true
                    case "false":
                        actual = false
                    default:
                        actual = value
                }
            } else {
                actual = value
            }
            
            // Rebuild policy group as json array.
            guard parser.currentGroup != Configuration.CodingKeys.selectablePolicyGroups.rawValue else {
                var array: [Any] = (json[parser.currentGroup] as? [Any]) ?? []
                let _json = [
                    SelectablePolicyGroup.CodingKeys.name.rawValue : next.key.trimmingCharacters(in: .whitespaces),
                    SelectablePolicyGroup.CodingKeys.policies.rawValue : actual
                ]
                array.append(_json)
                json[parser.currentGroup] = array
                return
            }
            
            // Rebuild policies as json array.
            guard parser.currentGroup != Configuration.CodingKeys.policies.rawValue else {
                var array: [Any] = (json[parser.currentGroup] as? [Any]) ?? []
                array.append("\(next.key)=\(next.value)")
                json[parser.currentGroup] = array
                return
            }
            
            if next.key == Cursor.markableLine.rawValue {
                var array: [Any] = (json[parser.currentGroup] as? [Any]) ?? []
                array.append(actual)
                json[parser.currentGroup] = array
            } else {
                var _json = (json[parser.currentGroup] as? [String : Any]) ?? [:]
                _json[next.key.trimmingCharacters(in: .whitespaces)] = actual
                json[parser.currentGroup] = _json
            }
        }
        
        return json
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
            stringLiteral.append("\(key)\n")
            
            if key == Configuration.CodingKeys.selectablePolicyGroups.rawValue {
                if let selectablePolicyGroups = value as? [[String : Any]] {
                    selectablePolicyGroups.forEach {
                        stringLiteral.append("\($0[SelectablePolicyGroup.CodingKeys.name.rawValue]!) = \($0[SelectablePolicyGroup.CodingKeys.policies.rawValue]!)\n")
                    }
                }
            } else {
                if let array = value as? [Any] {
                    array.forEach {
                        stringLiteral.append("\($0)\n")
                    }
                } else if let dictionary = value as? [String : Any] {
                    dictionary.keys.sorted().forEach {
                        stringLiteral.append("\($0) = \(String(describing: dictionary[$0]))\n")
                    }
                }
            }
        }
        
        return stringLiteral.data(using: .utf8) ?? .init()
    }
    
    func parse() throws -> [Line] {
        var ruleLineMap: [Int : Line] = [:]
        var policyGroupMap: [Int : Line] = [:]
        var proxyMap: [Int : Line] = [:]
        let builtin: [Line] = [
            .init(key: "DIRECT", value: ""),
            .init(key: "REJECT", value: ""),
            .init(key: "REJECT-TINYGIF", value: ""),
        ]
        
        var lines: [Line] = []
        while let next = self.parseNext() {
            cursor += 1
            
            lines.append(next)
            
            guard next.key != Cursor.commentLine.rawValue, next.key != Cursor.newLine.rawValue else {
                continue
            }
            
            guard next.key != Cursor.mdlLine.rawValue else {
                currentGroup = next.value.trimmingCharacters(in: .whitespaces)
                continue
            }
            
            switch currentGroup {
                case Configuration.CodingKeys.selectablePolicyGroups.rawValue:
                    policyGroupMap[cursor] = next
                case Configuration.CodingKeys.rules.rawValue:
                    ruleLineMap[cursor] = next
                case Configuration.CodingKeys.policies.rawValue:
                    proxyMap[cursor] = next
                default:
                    break
            }
        }
        
        // All proxy used in policy group must declare in [Proxy].
        try policyGroupMap.forEach { (cursor, line) in
            try line.value
                .split(separator: ",")
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .forEach { name in
                    let contains = proxyMap.values.contains { l in
                        l.key.trimmingCharacters(in: .whitespaces) == name
                    } || builtin.contains { l in
                        l.key.trimmingCharacters(in: .whitespaces) == name
                    }
                    guard name == "select" || contains else {
                        throw ConfigurationSerializationError.invalidFile(reason: .unknownPolicy(cursor: cursor, policy: name))
                    }
                }
        }
        
        try ruleLineMap.forEach { (cursor, line) in
            guard let rule = try? AnyRule.init(stringLiteral: line.value) else {
                throw ConfigurationSerializationError.invalidFile(reason: .invalidLine(cursor: cursor, description: line.value))
            }
            // Validate rule policy.
            let contains = proxyMap.values.contains {
                $0.key.trimmingCharacters(in: .whitespaces) == rule.policy
            } || policyGroupMap.values.contains {
                $0.key.trimmingCharacters(in: .whitespaces) == rule.policy
            } || builtin.contains {
                $0.key.trimmingCharacters(in: .whitespaces) == rule.policy
            }
            guard contains else {
                throw ConfigurationSerializationError.invalidFile(reason: .unknownPolicy(cursor: cursor, policy: rule.policy))
            }
        }
        
        // Reset `currentGroup` to initial value.
        currentGroup = ""
        return lines
    }
    
    private func parseNext() -> Line? {
        self.skipSpaces()
        
        guard let peek = self.peek() else {
            return nil
        }
        
        switch (peek, previous) {
            case (.octothorpe, _), (.semicolon, _):
                self.previous = peek
                return Line(key: Cursor.commentLine.rawValue, value: self.parseLineValue())
            case (0x5b, _):
                self.previous = peek
                return Line(key: Cursor.mdlLine.rawValue, value: self.parseLineValue())
            case (.newLine, .some(.newLine)):
                self.pop()
                self.previous = peek
                return Line(key: Cursor.newLine.rawValue, value: "\n")
            case (.newLine, _):
                // empty line, skip
                self.pop()
                // then parse next
                self.previous = peek
                return self.parseNext()
            default:
                self.previous = peek
                // this is a valid line, parse it
                return self.parseLine()
        }
    }
    
    private func skipSpaces() {
        while let next = self.peek() {
            guard case .space = next else {
                break
            }
            self.pop()
        }
    }
    
    private func parseLine() -> Line {
        let distance = self.source.countDistance(to: .equal)
        let maxLength = self.source.countDistance(to: .newLine) ?? self.source.readableBytes
        
        // Ensure that have equal mark and the equal is in current line.
        // FIXME: Think about `.equal` is the end of line.
        guard let distance = distance, distance <= maxLength else {
            return Line(key: Cursor.markableLine.rawValue, value: self.parseLineValue())
        }
        
        let key = self.source.readString(length: distance)!
        
        self.pop() // =
        
        return Line(key: key, value: self.parseLineValue())
    }
    
    private func parseLineValue() -> String {
        let valueLength: Int
        if let toNewLine = self.source.countDistance(to: .newLine) {
            valueLength = toNewLine
        } else {
            valueLength = self.source.readableBytes
        }
        
        let value = self.source.readString(length: valueLength)!
        
        guard let first = value.first, let last = value.last else {
            return value
        }
        // check for quoted strings
        switch (first, last) {
            case ("\"", "\""):
                // double quoted strings support escaped \n
                return value.dropFirst().dropLast()
                    .replacingOccurrences(of: "\\n", with: "\n")
            case ("'", "'"):
                // single quoted strings just need quotes removed
                return value.dropFirst().dropLast() + ""
            default: return value
        }
    }
    
    private func peek() -> UInt8? {
        return self.source.getInteger(at: self.source.readerIndex)
    }
    
    private func pop() {
        self.source.moveReaderIndex(forwardBy: 1)
    }
}

extension ByteBuffer {
    
    fileprivate func countDistance(to byte: UInt8) -> Int? {
        var copy = self
        var found = false
        while let next = copy.readInteger(as: UInt8.self) {
            if next == byte {
                found = true
                break
            }
        }
        guard found else {
            return nil
        }
        let distance = copy.readerIndex - self.readerIndex
        guard distance != 0 else {
            return nil
        }
        return distance - 1
    }
}

extension UInt8 {
    fileprivate static var newLine: UInt8 {
        return 0xA
    }
    
    fileprivate static var space: UInt8 {
        return 0x20
    }
    
    fileprivate static var octothorpe: UInt8 {
        return 0x23
    }
    
    fileprivate static var semicolon: UInt8 {
        return 0x3b
    }
    
    fileprivate static var equal: UInt8 {
        return 0x3D
    }
}
