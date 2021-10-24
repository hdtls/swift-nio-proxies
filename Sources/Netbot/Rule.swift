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
import Helpers
import CMMDB

public enum RuleType: String, Codable, CaseIterable {
    case domain = "DOMAIN"
    case domainSuffix = "DOMAIN-SUFFIX"
    case domainKeyword = "DOMAIN-KEYWORD"
        case domainSet = "DOMAIN-SET"
    case final = "FINAL"
    case geoip = "GEOIP"
        case ipcidr = "IP-CIDR"
        case processName = "PROCESS-NAME"
    case ruleSet = "RULE-SET"
}

public protocol RuleProtocol: Codable {
    var type: RuleType { get set }
    var policy: String { get set }
    var comment: String? { get set }
    func match(_ pattern: String) -> Bool
}

public struct Rule: Codable, RuleProtocol {
    
    public var type: RuleType
    public var pattern: String?
    public var policy: String
    public var comment: String?
    
    static let `default`: Rule = "FINAL,DIRECT,dns-failed"
    
    public init(string: String) throws {
        let parts = string.split(separator: ",").map(String.init)
        guard parts.count >= 2 else {
            throw ParserError.invalidFile(reason: .dataCorrupted)
        }
        
        guard let t = RuleType(rawValue: parts.first!.trimmingCharacters(in: .whitespaces)) else {
            throw ParserError.invalidFile(reason: .dataCorrupted)
        }
        
        type = t
        
        if t == .final {
            if parts[1].contains("//") {
                let splited = parts[1].components(separatedBy: "//")
                policy = splited.first!.trimmingCharacters(in: .whitespaces)
                comment = splited.last!.trimmingCharacters(in: .whitespaces)
            } else {
                policy = parts[1].trimmingCharacters(in: .whitespaces)
            }
        } else {
            guard parts.count >= 3 else {
                throw ParserError.invalidFile(reason: .dataCorrupted)
            }
            pattern = parts[1].trimmingCharacters(in: .whitespaces)
            if parts[2].contains("//") {
                let splited = parts[2].components(separatedBy: "//")
                policy = splited.first!.trimmingCharacters(in: .whitespaces)
                comment = splited.last!.trimmingCharacters(in: .whitespaces)
            } else {
                policy = parts[2].trimmingCharacters(in: .whitespaces)
            }
        }
    }
    
    public init(from decoder: Decoder) throws {
        let singleValueContainer = try decoder.singleValueContainer()
        let stringLiteral = try singleValueContainer.decode(String.self)
        try self.init(string: stringLiteral)
    }
    
    public func encode(to encoder: Encoder) throws {
        var singleValueContainer = encoder.singleValueContainer()
        let stringLiteral = "\(type.rawValue),\(pattern != nil ? pattern! + "," : "")\(policy)\(comment != nil ? " // \(comment!)" : "")"
        try singleValueContainer.encode(stringLiteral)
    }
    
    public func match(_ pattern: String) -> Bool {
        switch type {
            case .domain:
                return self.pattern == pattern
            case .domainSuffix:
                return pattern.hasSuffix(self.pattern!)
            case .domainKeyword:
                return pattern.contains(self.pattern!)
            case .final:
                return false
            case .geoip:
                return self.pattern == pattern
            default:
                assertionFailure()
                return false
        }
    }
}

extension Rule: ExpressibleByStringLiteral {
    public typealias StringLiteralType = String
    
    public init(stringLiteral value: String) {
        try! self.init(string: value)
    }
}
