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

import Crypto
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import MaxMindDB

public enum RuleTag: String, CaseIterable {
    case domain = "DOMAIN"
    case domainSuffix = "DOMAIN-SUFFIX"
    case domainKeywords = "DOMAIN-KEYWORD"
    case domainSet = "DOMAIN-SET"
    case ruleSet = "RULE-SET"
    case geoIp = "GEOIP"
    case final = "FINAL"
    
    var representRuleMeta: Rule.Type {
        switch self {
            case .domain:
                return DomainRule.self
            case .domainSuffix:
                return DomainSuffixRule.self
            case .domainKeywords:
                return DomainKeywordRule.self
            case .domainSet:
                return DomainSet.self
            case .ruleSet:
                return RuleSet.self
            case .geoIp:
                return GeoIPRule.self
            case .final:
                return FinalRule.self
        }
    }
}

/// `Rule` protocol define basic rule object protocol.
public protocol Rule: Codable {
    
    /// The rule ID, this should be unique for each type of rule.
    static var tag: RuleTag { get }
        
    /// The expression fot this rule.
    ///
    /// If rule is collection expression is used to save external resources url string.
    var expression: String { get set }
    
    /// The policy pointed to by the rule.
    var policy: String { get set }
    
    /// The comment for this rule.
    var comment: String? { get set }
    
    /// Rule evaluating function to determinse whether this rule match the given expression.
    /// - Returns: True if match else false.
    func match(_ pattern: String) -> Bool
    
    /// Initialize an instance of `Rule` with specified string.
    init(stringLiteral: String) throws
}

extension Rule {
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        try self.init(stringLiteral: container.decode(String.self))
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode("\(Self.tag.rawValue),\(expression),\(policy)\(comment != nil ? " // \(comment!)" : "")")
    }
}

extension Rule {
    
    public var description: String {
        "\(Self.tag) \(self.expression) \(self.policy)"
    }
}

private protocol RulePrivate: Rule {
    
    /// Empty initlization.
    init()
}

extension RulePrivate {
    
    public init(stringLiteral: String) throws {
        var components = stringLiteral.components(separatedBy: ",")
        guard components.count >= 3 else {
            throw ConfigurationSerializationError.failedToParseRule(reason: .missingField)
        }
        
        let rawValue = components.removeFirst().trimmingCharacters(in: .whitespaces)
        guard let tag = RuleTag(rawValue: rawValue) else {
            throw ConfigurationSerializationError.failedToParseRule(reason: .unsupported)
        }

        guard Self.tag == tag else {
            throw ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(Self.self, butCanBeParsedAs: tag.representRuleMeta))
        }
        
        assert(RuleTag.allCases.contains(where: { $0 == tag }))
        self.init()
        
        expression = components.removeFirst().trimmingCharacters(in: .whitespaces)
        components = components[0].components(separatedBy: "//")
        
        guard components.count >= 2 else {
            policy = components[0].trimmingCharacters(in: .whitespaces)
            return
        }
        policy = components.first!.trimmingCharacters(in: .whitespaces)
        comment = components[1].trimmingCharacters(in: .whitespaces)
    }
}

/// `RuleCollection` is a special rule that it's expression is an URL of which external resources hosted.
public protocol RuleCollection: Rule {
    
    /// All rules contains in this collection.
    var standardRules: [Rule] { get }
    
    /// A boolean value determinse whether rule collection should perform downloading external resources.
    /// default is true.
    var shouldPerformDownloading: Bool { get }

    /// Reload rule data from file store in `dstURL`.
    func reloadData()
}

extension RuleCollection {
    
    /// External resources storage url.
    public var dstURL: URL {
        if let url = URL(string: expression), url.isFileURL {
            return url
        }
        
        let filename = Insecure.SHA1.hash(data: Data(expression.utf8))
            .compactMap { String(format: "%02x", $0) }
            .joined()
        
        var dstURL = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
        
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
    
    public var shouldPerformDownloading: Bool {
        true
    }
    
    /// Load external resources from url resolved with expression and a completion will invoke whenever success or failed.
    ///
    /// If expression is file url or is not a valid url string thist will finished with `.invalidExteranlResources` error.
    /// else start downloading resources from that url and save downloaded file to `dstURL`,
    /// after that `reloadData()` will be call and completed with resolved standard rules.
    public func performLoadingExternalResources(completion: @escaping (Result<[Rule], Error>) -> Void) {
        guard shouldPerformDownloading else {
            self.reloadData()
            completion(.success(self.standardRules))
            return
        }
        
        guard let url = URL(string: expression), !url.isFileURL else {
            completion(.failure(ConfigurationSerializationError.failedToParseRule(reason: .invalidExternalResources)))
            return
        }
        
        URLSession.shared.downloadTask(with: url) { srcURL, response, error in
            guard error == nil else {
                completion(.failure(error!))
                return
            }
            
            guard let srcURL = srcURL else {
                completion(.success([]))
                return
            }
            
            do {
                // Remove older file first if exists.
                if FileManager.default.fileExists(atPath: self.dstURL.path) {
                    try FileManager.default.removeItem(at: self.dstURL)
                }
                try FileManager.default.moveItem(at: srcURL, to: self.dstURL)
                self.reloadData()
                completion(.success(self.standardRules))
            } catch {
                self.reloadData()
                completion(.failure(error))
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

extension Equatable where Self: RuleCollection {

    public static func ==(lhs: Self, rhs: Self) -> Bool {
        lhs.expression == rhs.expression
        && lhs.policy == rhs.policy
        && lhs.comment == rhs.comment
    }
}

private protocol RuleCollectionPrivate: RuleCollection, RulePrivate {}

extension RuleCollectionPrivate {
    
    public init(stringLiteral: String) throws {
        var components = stringLiteral.components(separatedBy: ",")
        guard components.count >= 3 else {
            throw ConfigurationSerializationError.failedToParseRule(reason: .missingField)
        }
        
        guard let tag = RuleTag(rawValue: components.removeFirst().trimmingCharacters(in: .whitespaces)) else {
            throw ConfigurationSerializationError.failedToParseRule(reason: .unsupported)
        }
        
        guard Self.tag == tag else {
            throw ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(Self.self, butCanBeParsedAs: tag.representRuleMeta))
        }
        
        assert(RuleTag.allCases.contains(where: { $0 == tag }))

        self.init()
        
        expression = components.removeFirst().trimmingCharacters(in: .whitespaces)
        components = components[0].components(separatedBy: "//")
        
        guard components.count >= 2 else {
            policy = components[0].trimmingCharacters(in: .whitespaces)
            
            performLoadingExternalResources { _ in }
            return
        }
        policy = components.first!.trimmingCharacters(in: .whitespaces)
        comment = components[1].trimmingCharacters(in: .whitespaces)
        
        performLoadingExternalResources { _ in }
    }
}

/// `DomainRule` use domain as expression and matches the full domain name when evaluating.
public struct DomainRule: Codable, Equatable, RulePrivate {
    
    public static let tag: RuleTag = .domain
    
    public var expression: String
    
    public var policy: String
    
    public var comment: String?
    
    fileprivate init() {
        self.expression = "*"
        self.policy = "direct"
    }
    
    public func match(_ pattern: String) -> Bool {
        self.expression == pattern
    }
}

/// `DomainSuffixRule` use domain suffix as expression and matches the full domain name or suffix when evaluating.
public struct DomainSuffixRule: Codable, Equatable, RulePrivate {
    
    public static let tag: RuleTag = .domainSuffix
    
    public var expression: String
    
    public var policy: String
    
    public var comment: String?
    
    fileprivate init() {
        self.expression = "*"
        self.policy = "direct"
    }
    
    public func match(_ pattern: String) -> Bool {
        // e.g. apple.com should match *.apple.com and apple.com
        // should not match *apple.com.
        self.expression == pattern || ".\(pattern)".hasSuffix(self.expression)
    }
}

/// `DomainKeywordRule` use domain keyword as expression and matches whether domain contains expression when evaluating.
public struct DomainKeywordRule: Codable, Equatable, RulePrivate {
    
    public static let tag: RuleTag = .domainKeywords
    
    public var expression: String
    
    public var policy: String
    
    public var comment: String?
    
    fileprivate init() {
        self.expression = "*"
        self.policy = "direct"
    }
    
    public func match(_ pattern: String) -> Bool {
        pattern.contains(self.expression)
    }
}

/// `DomainSet` rules contains a lot of `DomainSuffixRule` as it's external resources.
public struct DomainSet: Codable, Equatable, RuleCollectionPrivate {
    
    public static let tag: RuleTag = .domainSet
    
    public var expression: String
    
    public var policy: String
    
    public var comment: String?
    
    @Protected private var _standardRules: [Rule] = []
    public var standardRules: [Rule] {
        _standardRules
    }
    
    fileprivate init() {
        expression = "*"
        policy = "direct"
    }
    
    public func reloadData() {
        guard let data = try? Data(contentsOf: dstURL), let file = String(data: data, encoding: .utf8) else {
            return
        }
        
        self._standardRules = file.split(separator: "\n")
            .compactMap {
                let literal = $0.trimmingCharacters(in: .whitespaces)
                guard !literal.isEmpty else {
                    return nil
                }
                return try? DomainSuffixRule(stringLiteral: "\(DomainSuffixRule.tag.rawValue),\(literal),\(policy)")
            }
    }
}

/// `GeoIPRule` use ip string as expression and matches country ISO code search from `GeoLite2` when evaluating.
public struct GeoIPRule: Codable, Equatable, RulePrivate {
    
    public static let tag: RuleTag = .geoIp
    
    @Protected static var geo: MaxMindDB?
    
    public var expression: String
    
    public var policy: String
    
    public var comment: String?
    
    fileprivate init() {
        expression = "*"
        policy = "direct"
    }
    
    public func match(_ pattern: String) -> Bool {
        do {
            let dictionary = try GeoIPRule.geo?.lookup(ipAddress: pattern) as? [String : [String : Any]]
            let country = dictionary?["country"]
            let countryCode = country?["iso_code"] as? String
            return self.expression == countryCode
        } catch {
            return false
        }
    }
}

public struct FinalRule: Codable, Equatable, RulePrivate {
    
    public static let tag: RuleTag = .final
    
    public var expression: String
    
    public var policy: String
    
    public var comment: String?
    
    fileprivate init() {
        expression = "dns-failed"
        policy = "direct"
    }
    
    public func match(_ pattern: String) -> Bool {
        true
    }
}

public struct RuleSet: Codable, Equatable, RuleCollectionPrivate {
    
    public static let tag: RuleTag = .ruleSet
    
    public var expression: String
    
    public var policy: String
    
    public var comment: String?
    
    @Protected private var _standardRules: [Rule] = []
    public var standardRules: [Rule] {
        _standardRules
    }
    
    public var shouldPerformDownloading: Bool {
        return expression != "SYSTEM" && expression != "LAN"
    }
    
    fileprivate init() {
        expression = "*"
        policy = "direct"
    }
    
    public func reloadData() {
        guard let data = try? Data(contentsOf: dstURL), let file = String(data: data, encoding: .utf8) else {
            // Builtin rule collection is not supported yet.
            guard expression != "SYSTEM", expression != "LAN" else {
                return
            }
            return
        }
        
        self._standardRules = file.split(separator: "\n")
            .compactMap {
                let literal = $0.trimmingCharacters(in: .whitespaces)
                guard !literal.isEmpty else {
                    return nil
                }
                return try? AnyRule(stringLiteral: literal + ",\(policy)")
            }
    }
}

/// A type-erased rule value.
///
/// The `AnyRule` type forwards match coding and equality comparisons operations
/// to an underlying rule value, hiding the type of the wrapped value.
public struct AnyRule: Codable, Rule {
    
    public static var tag: RuleTag {
        fatalError("\(#function) is unavailable, use each rule's class methods instead.")
    }
    
    public var expression: String {
        set { base.expression = newValue }
        get { base.expression }
    }
    
    public var policy: String {
        set { base.policy = newValue }
        get { base.policy }
    }
    
    public var comment: String? {
        set { base.comment = newValue }
        get { base.comment }
    }
    
    /// The value wrapped by this instance.
    ///
    /// The `base` property can be cast back to its original type using one of
    /// the type casting operators (`as?`, `as!`, or `as`).
    public var base: Rule
    
    /// Creates a type-erased rule value that wraps the given instance.
    /// - Parameter base: A rule value to wrap.
    public init<R>(_ base: R) where R: Rule {
        self.base = base
    }
    
    public init(stringLiteral: String) throws {
        switch RuleTag(rawValue: stringLiteral.components(separatedBy: ",").first!.trimmingCharacters(in: .whitespaces)) {
            case DomainRule.tag:
                self = .init(try DomainRule(stringLiteral: stringLiteral))
            case DomainSuffixRule.tag:
                self = .init(try DomainSuffixRule(stringLiteral: stringLiteral))
            case DomainKeywordRule.tag:
                self = .init(try DomainKeywordRule(stringLiteral: stringLiteral))
            case DomainSet.tag:
                self = .init(try DomainSet(stringLiteral: stringLiteral))
            case FinalRule.tag:
                self = .init(try FinalRule(stringLiteral: stringLiteral))
            case GeoIPRule.tag:
                self = .init(try GeoIPRule(stringLiteral: stringLiteral))
            case RuleSet.tag:
                self = .init(try RuleSet(stringLiteral: stringLiteral))
            default:
                throw ConfigurationSerializationError.failedToParseRule(reason: .unsupported)
        }
    }
    
    public func encode(to encoder: Encoder) throws {
        try base.encode(to: encoder)
    }
    
    public func match(_ pattern: String) -> Bool {
        base.match(pattern)
    }
}

extension AnyRule: CustomStringConvertible {
    
    public var description: String {
        base.description
    }
}

extension AnyRule: Equatable {
    
    public static func == (lhs: AnyRule, rhs: AnyRule) -> Bool {
        lhs.expression == rhs.expression
        && lhs.policy == rhs.policy
        && lhs.comment == rhs.comment
    }
}
