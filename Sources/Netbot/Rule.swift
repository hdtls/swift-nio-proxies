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

#if compiler(>=5.1)
@_implementationOnly import CMMDB
#else
import CMMDB
#endif
import Crypto
import Foundation
import Helpers

public enum RuleType: String, Codable, CaseIterable {
    case domain = "DOMAIN"
    case domainSuffix = "DOMAIN-SUFFIX"
    case domainKeyword = "DOMAIN-KEYWORD"
    case domainSet = "DOMAIN-SET"
    case userAgent = "USER-AGENT"
    case final = "FINAL"
    case geoip = "GEOIP"
    case ipcidr = "IP-CIDR"
    case processName = "PROCESS-NAME"
    case ruleSet = "RULE-SET"
}

public protocol Rule: Codable {
    var type: RuleType { get set }
    var pattern: String { get set }
    var policy: String { get set }
    var comment: String? { get set }
    func match(_ pattern: String) -> Bool
    
    init(string: String) throws
}

extension Rule {
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        try self.init(string: container.decode(String.self))
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode("\(type.rawValue),\(pattern),\(policy)\(comment != nil ? " // \(comment!)" : "")")
    }
}

public protocol RuleCollection: Rule {
    
    var standardRules: [StandardRule] { get }
    
    // Reload rule data.
    func reloadData()
}

extension RuleCollection {
    
    /// External resources storage url.
    var dstURL: URL {
        if let url = URL(string: pattern), url.isFileURL {
            return url
        }
        
        let filename = Insecure.SHA1.hash(data: Data(pattern.utf8))
            .compactMap { String(format: "%02x", $0) }
            .joined()
        
#if os(iOS) || os(macOS) || os(tvOS)
        var dstURL = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
#else
        
#endif
        dstURL.appendPathComponent("io.tenbits.Netbot")
        dstURL.appendPathComponent("External Resources")
        do {
            try FileManager.default.createDirectory(at: dstURL, withIntermediateDirectories: true)
        } catch {
            assertionFailure(error.localizedDescription)
        }
        dstURL.appendPathComponent(filename)
        return dstURL
    }
    
    /// Perform external resources loading.
    func performLoading() {
        guard let url = URL(string: pattern), !url.isFileURL else {
            return
        }
        URLSession.shared.downloadTask(with: url) { srcURL, response, error in
            guard let srcURL = srcURL, error == nil else {
                return
            }
            do {
                // Remove older file first if exists.
                if FileManager.default.fileExists(atPath: self.dstURL.path) {
                    try FileManager.default.removeItem(at: self.dstURL)
                }
                try FileManager.default.moveItem(at: srcURL, to: self.dstURL)
                self.reloadData()
            } catch {
                assertionFailure(error.localizedDescription)
            }
        }.resume()
    }
}

public struct StandardRule: Rule {
    
    public var type: RuleType
    public var pattern: String
    public var policy: String
    public var comment: String?
    
    public init(string: String) throws {
        let parts = string.split(separator: ",").map(String.init)
        guard parts.count >= 3 else {
            throw ParserError.invalidFile(reason: .dataCorrupted)
        }
        
        guard let t = RuleType(rawValue: parts.first!.trimmingCharacters(in: .whitespaces)) else {
            throw ParserError.invalidFile(reason: .dataCorrupted)
        }
        
        assert(t != .domainSet && t != .ruleSet, "assert illegal rule type.")
        
        type = t
        pattern = parts[1].trimmingCharacters(in: .whitespaces)
        if parts[2].contains("//") {
            let splited = parts[2].components(separatedBy: "//")
            policy = splited.first!.trimmingCharacters(in: .whitespaces)
            comment = splited.last!.trimmingCharacters(in: .whitespaces)
        } else {
            policy = parts[2].trimmingCharacters(in: .whitespaces)
        }
    }
    
    public func match(_ pattern: String) -> Bool {
        switch type {
            case .domain, .processName:
                return self.pattern == pattern
            case .domainSuffix:
                return pattern.hasSuffix(self.pattern)
            case .domainKeyword:
                return pattern.contains(self.pattern)
            case .userAgent:
                // TODO: USER-AGENT match support.
                return false
            case .ipcidr:
                return false
            default:
                assertionFailure()
                return false
        }
    }
}

/// GEOIP,CN,DIRECT
public struct GeoIPRule: Rule {
    
    @Protected public static var geo: GeoLite2?
    
    public var type: RuleType
    public var pattern: String
    public var policy: String
    public var comment: String?
    
    public init(string: String) throws {
        let parts = string.split(separator: ",").map(String.init)
        guard parts.count >= 3 else {
            throw ParserError.invalidFile(reason: .dataCorrupted)
        }
        
        guard let t = RuleType(rawValue: parts.first!.trimmingCharacters(in: .whitespaces)) else {
            throw ParserError.invalidFile(reason: .dataCorrupted)
        }
        
        assert(t == .geoip, "assert illegal rule type.")
        
        type = t
        pattern = parts[1].trimmingCharacters(in: .whitespaces)
        if parts[2].contains("//") {
            let splited = parts[2].components(separatedBy: "//")
            policy = splited.first!.trimmingCharacters(in: .whitespaces)
            comment = splited.last!.trimmingCharacters(in: .whitespaces)
        } else {
            policy = parts[2].trimmingCharacters(in: .whitespaces)
        }
    }
    
    public func match(_ pattern: String) -> Bool {
        do {
            let countryCode = try GeoIPRule.geo?.queryCountryISOCodeWithIPAddress(pattern)
            return self.pattern == countryCode
        } catch {
            return false
        }
    }
}

/// FINAL,PROXY,dns-failed
public struct FinalRule: Rule {
    
    public var type: RuleType
    public var pattern: String
    public var policy: String
    public var comment: String?
    
    public init(string: String) throws {
        let parts = string.split(separator: ",").map(String.init)
        guard parts.count >= 3 else {
            throw ParserError.invalidFile(reason: .dataCorrupted)
        }
        
        guard let t = RuleType(rawValue: parts.first!.trimmingCharacters(in: .whitespaces)) else {
            throw ParserError.invalidFile(reason: .dataCorrupted)
        }
        
        precondition(parts[2] == "dns-failed", "unsupported pattern \(String(describing: parts[2])).")
        assert(t == .final, "assert illegal rule type.")
        type = t
        policy = parts[1].trimmingCharacters(in: .whitespaces)
        pattern = parts[2]
    }
    
    public func match(_ pattern: String) -> Bool {
        true
    }
}

final public class DomainSet: RuleCollection {
    
    public var type: RuleType
    public var pattern: String
    public var policy: String
    public var comment: String?
    
    @Protected var _standardRules: [StandardRule] = []
    public var standardRules: [StandardRule] {
        _standardRules
    }
    
    public init(string: String) throws {
        let parts = string.split(separator: ",").map(String.init)
        guard parts.count >= 3 else {
            throw ParserError.invalidFile(reason: .dataCorrupted)
        }
        
        guard let t = RuleType(rawValue: parts.first!.trimmingCharacters(in: .whitespaces)) else {
            throw ParserError.invalidFile(reason: .dataCorrupted)
        }
        assert(t == .domainSet, "assert illegal rule type.")
        
        type = t
        pattern = parts[1].trimmingCharacters(in: .whitespaces)
        if parts[2].contains("//") {
            let components = parts[2].components(separatedBy: "//")
            policy = components.first!.trimmingCharacters(in: .whitespaces)
            comment = components.last!.trimmingCharacters(in: .whitespaces)
        } else {
            policy = parts[2].trimmingCharacters(in: .whitespaces)
        }
        
        reloadData()
    }
    
    public func reloadData() {
        guard let data = try? Data(contentsOf: dstURL), let file = String(data: data, encoding: .utf8) else {
            self.performLoading()
            return
        }
        var rules: [StandardRule] = []
        file.split(separator: "\n")
            .forEach {
                let literal = $0.trimmingCharacters(in: .whitespaces)
                guard !literal.isEmpty else {
                    return
                }
                rules.append(try! .init(string: "\(RuleType.domainSuffix.rawValue),\(literal),\(policy)"))
            }
        self._standardRules = rules
    }
    
    public func match(_ pattern: String) -> Bool {
        standardRules.first {
            $0.match(pattern)
        } != nil
    }
}

final public class RuleSet: RuleCollection {
    
    public var type: RuleType
    public var pattern: String
    public var policy: String
    public var comment: String?
    
    @Protected var _standardRules: [StandardRule] = []
    public var standardRules: [StandardRule] {
        _standardRules
    }
    
    public init(string: String) throws {
        let parts = string.split(separator: ",").map(String.init)
        guard parts.count >= 3 else {
            throw ParserError.invalidFile(reason: .dataCorrupted)
        }
        
        guard let t = RuleType(rawValue: parts.first!.trimmingCharacters(in: .whitespaces)) else {
            throw ParserError.invalidFile(reason: .dataCorrupted)
        }
        
        assert(t == .ruleSet, "assert illegal rule type.")
        
        type = t
        pattern = parts[1].trimmingCharacters(in: .whitespaces)
        if parts[2].contains("//") {
            let components = parts[2].components(separatedBy: "//")
            policy = components.first!.trimmingCharacters(in: .whitespaces)
            comment = components.last!.trimmingCharacters(in: .whitespaces)
        } else {
            policy = parts[2].trimmingCharacters(in: .whitespaces)
        }
        
        reloadData()
    }
    
    public func reloadData() {
        guard let data = try? Data(contentsOf: dstURL), let file = String(data: data, encoding: .utf8) else {
            // Builtin rule collection is not supported yet.
            guard pattern != "SYSTEM", pattern != "LAN" else {
                return
            }
            self.performLoading()
            return
        }
        
        var rules: [StandardRule] = []
        file.split(separator: "\n")
            .forEach {
                var literal = $0.trimmingCharacters(in: .whitespaces)
                guard !literal.isEmpty else {
                    return
                }
                literal.append(",\(policy)")
                
                guard let standardRule = try? StandardRule.init(string: literal) else {
                    // .dataCorrupted
                    return
                }
                rules.append(standardRule)
            }
        self._standardRules = rules
    }
    
    public func match(_ pattern: String) -> Bool {
        standardRules.first {
            $0.match(pattern)
        } != nil
    }
}

/// A type-erased rule.
public struct AnyRule: Rule {
    
    public var type: RuleType {
        set {
            underlying.type = newValue
        }
        get {
            underlying.type
        }
    }
    
    public var pattern: String {
        set {
            underlying.pattern = newValue
        }
        get {
            underlying.pattern
        }
    }
    
    public var policy: String {
        set {
            underlying.policy = newValue
        }
        get {
            underlying.policy
        }
    }
    
    public var comment: String? {
        set {
            underlying.comment = newValue
        }
        get {
            underlying.comment
        }
    }
    
    var underlying: Rule
    
    public init(underlying: Rule) {
        self.underlying = underlying
    }
    
    public init(string: String) throws {
        guard let type = RuleType.init(rawValue: string.components(separatedBy: ",").first!) else {
            throw ParserError.dataCorrupted
        }
        switch type {
            case .domain, .domainSuffix, .domainKeyword, .processName, .userAgent:
                self = .init(underlying: try StandardRule.init(string: string))
            case .domainSet:
                self = .init(underlying: try DomainSet.init(string: string))
            case .final:
                self = .init(underlying: try FinalRule.init(string: string))
            case .geoip:
                self = .init(underlying: try GeoIPRule.init(string: string))
            case .ipcidr:
                self = .init(underlying: try StandardRule.init(string: string))
            case .ruleSet:
                self = .init(underlying: try RuleSet.init(string: string))
        }
    }
    
    public func encode(to encoder: Encoder) throws {
        try underlying.encode(to: encoder)
    }
    
    public func match(_ pattern: String) -> Bool {
        underlying.match(pattern)
    }
}

final public class RuleMatcher {
    
    /// The rule list.
    public let rules: [Rule]
    
    public init(rules: [Rule]) {
        self.rules = rules
    }
    
    /// Returns the first matched element of the `rules` sequence that satisfies the given
    /// pattern.
    ///
    /// - Parameter pattern: Pattern used to evaluate match.
    /// - Returns: The first matched element of the sequence that satisfies `pattern`,
    ///   or `nil` if there is no element that satisfies `pattern`.
    public func firstMatch(_ pattern: String) -> Rule? {
        var match: Rule?
        var dnsFailedRule: Rule?
        
        for rule in rules {
            if rule.match(pattern) {
                match = rule
                break
            }
            
            if rule.type == .final {
                dnsFailedRule = rule
            }
        }
        return match ?? dnsFailedRule
    }
}
