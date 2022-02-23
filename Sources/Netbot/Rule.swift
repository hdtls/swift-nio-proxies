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

fileprivate typealias CodableRule = Rule & Codable

public protocol Rule {
    var type: RuleType { get set }
    var pattern: String { get set }
    var policy: String { get set }
    var comment: String? { get set }
    func match(_ pattern: String) -> Bool
    
    init()
    init(stringLiteral: String) throws
}

extension Rule {
    
    public init(stringLiteral: String) throws {
        var components = stringLiteral.components(separatedBy: ",")
        guard components.count >= 3 else {
            throw ConfigurationSerializationError.invalidFile(reason: .dataCorrupted)
        }
        
        guard let t = RuleType(rawValue: components.removeFirst().trimmingCharacters(in: .whitespaces)) else {
            throw ConfigurationSerializationError.invalidFile(reason: .dataCorrupted)
        }
        
        self.init()
        
        type = t
        pattern = components.removeFirst().trimmingCharacters(in: .whitespaces)
        components = components[0].components(separatedBy: "//")
        
        guard components.count >= 2 else {
            policy = components[0].trimmingCharacters(in: .whitespaces)
            return
        }
        policy = components.first!.trimmingCharacters(in: .whitespaces)
        comment = components[1].trimmingCharacters(in: .whitespaces)
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        try self.init(stringLiteral: container.decode(String.self))
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

fileprivate typealias CodableRuleCollection = RuleCollection & Codable

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
    
    public func match(_ pattern: String) -> Bool {
        standardRules.first {
            $0.match(pattern)
        } != nil
    }
}

public struct StandardRule: CodableRule {
    
    public var type: RuleType
    public var pattern: String
    public var policy: String
    public var comment: String?
    
    public init() {
        type = .domain
        pattern = ""
        policy = "direct"
    }
    
    public func match(_ pattern: String) -> Bool {
        switch type {
            case .domain, .processName:
                return self.pattern == pattern
            case .domainSuffix:
                // e.g. apple.com should match *.apple.com and apple.com
                // should not match *apple.com.
                return self.pattern == pattern || ".\(pattern)".hasSuffix(self.pattern)
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
public struct GeoIPRule: CodableRule {
    
    @Protected static var geo: GeoLite2?
    
    public var type: RuleType
    public var pattern: String
    public var policy: String
    public var comment: String?
    
    public init() {
        type = .geoip
        pattern = ""
        policy = "direct"
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
public struct FinalRule: CodableRule {
    
    public var type: RuleType
    public var pattern: String
    public var policy: String
    public var comment: String?
    
    public init() {
        type = .final
        pattern = ""
        policy = "direct"
    }
    
    public init(stringLiteral: String) throws {
        var components = stringLiteral.components(separatedBy: ",")
        guard components.count >= 2 else {
            throw ConfigurationSerializationError.invalidRule(reason: .missingField)
        }
        
        guard let t = RuleType(rawValue: components.removeFirst().trimmingCharacters(in: .whitespaces)) else {
            throw ConfigurationSerializationError.invalidRule(reason: .unsupported)
        }
        
        assert(t == .final, "assert illegal rule type.")
        self.init()
        
        type = t
        
        if components.count == 1 {
            components = components[0].components(separatedBy: "//")
            policy = components[0].trimmingCharacters(in: .whitespaces)
            if components.count >= 2 {
                comment = components[1].trimmingCharacters(in: .whitespaces)
            }
        } else {
            policy = components[0].trimmingCharacters(in: .whitespaces)
            components = components[1].components(separatedBy: "//")
            pattern = components[0].trimmingCharacters(in: .whitespaces)
            if components.count >= 2 {
                comment = components[1].trimmingCharacters(in: .whitespaces)
            }
        }
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode("\(type.rawValue),\(policy)\(pattern.isEmpty ? "" : "," + pattern)\(comment != nil ? " // \(comment!)" : "")")
    }
    
    public func match(_ pattern: String) -> Bool {
        true
    }
}

final public class DomainSet: CodableRuleCollection {
    
    public var type: RuleType
    public var pattern: String
    public var policy: String
    public var comment: String?
    
    @Protected var _standardRules: [StandardRule] = []
    public var standardRules: [StandardRule] {
        _standardRules
    }
    
    public init() {
        type = .domainSet
        pattern = ""
        policy = "direct"
    }
    
    public init(stringLiteral: String) throws {
        let parts = stringLiteral.split(separator: ",").map(String.init)
        guard parts.count >= 3 else {
            throw ConfigurationSerializationError.invalidFile(reason: .dataCorrupted)
        }
        
        guard let t = RuleType(rawValue: parts.first!.trimmingCharacters(in: .whitespaces)) else {
            throw ConfigurationSerializationError.invalidFile(reason: .dataCorrupted)
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
                rules.append(try! .init(stringLiteral: "\(RuleType.domainSuffix.rawValue),\(literal),\(policy)"))
            }
        self._standardRules = rules
    }
}

final public class RuleSet: CodableRuleCollection {
    
    public var type: RuleType
    public var pattern: String
    public var policy: String
    public var comment: String?
    
    @Protected var _standardRules: [StandardRule] = []
    public var standardRules: [StandardRule] {
        _standardRules
    }
    
    public init() {
        type = .ruleSet
        pattern = ""
        policy = "direct"
    }
    
    public init(stringLiteral: String) throws {
        let parts = stringLiteral.split(separator: ",")
        guard parts.count >= 3 else {
            throw ConfigurationSerializationError.invalidFile(reason: .dataCorrupted)
        }
        
        guard let t = RuleType(rawValue: parts.first!.trimmingCharacters(in: .whitespaces)) else {
            throw ConfigurationSerializationError.invalidFile(reason: .dataCorrupted)
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
                
                guard let standardRule = try? StandardRule.init(stringLiteral: literal) else {
                    // .dataCorrupted
                    return
                }
                rules.append(standardRule)
            }
        self._standardRules = rules
    }
}

/// A type-erased rule.
public struct AnyRule: CodableRule {
    
    public var type: RuleType {
        set { underlying.type = newValue }
        get { underlying.type }
    }
    
    public var pattern: String {
        set { underlying.pattern = newValue }
        get { underlying.pattern }
    }
    
    public var policy: String {
        set { underlying.policy = newValue }
        get { underlying.policy }
    }
    
    public var comment: String? {
        set { underlying.comment = newValue }
        get { underlying.comment }
    }
    
    var underlying: Rule
    
    public init<R>(underlying: R) where R: Rule {
        self.underlying = underlying
    }
    
    public init() {
        self.init(underlying: FinalRule.init())
    }
    
    public init(stringLiteral: String) throws {
        guard let type = RuleType.init(rawValue: stringLiteral.components(separatedBy: ",").first!) else {
            throw ConfigurationSerializationError.dataCorrupted
        }
        switch type {
            case .domain, .domainSuffix, .domainKeyword, .processName, .userAgent:
                self = .init(underlying: try StandardRule.init(stringLiteral: stringLiteral))
            case .domainSet:
                self = .init(underlying: try DomainSet.init(stringLiteral: stringLiteral))
            case .final:
                self = .init(underlying: try FinalRule.init(stringLiteral: stringLiteral))
            case .geoip:
                self = .init(underlying: try GeoIPRule.init(stringLiteral: stringLiteral))
            case .ipcidr:
                self = .init(underlying: try StandardRule.init(stringLiteral: stringLiteral))
            case .ruleSet:
                self = .init(underlying: try RuleSet.init(stringLiteral: stringLiteral))
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
