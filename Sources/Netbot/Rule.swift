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

private let supportedRules: [Rule.Type] = [
    DomainRule.self,
    DomainSuffixRule.self,
    DomainKeywordRule.self,
    DomainSet.self,
    RuleSet.self,
    GeoIPRule.self,
    FinalRule.self
]

/// `Rule` protocol define basic rule object protocol.
public protocol Rule: Codable {
    
    /// The rule schema, this should be unique for each type of rule.
    static var schema: String { get }
    
    /// The rule pattern or external resources url string.
    var pattern: String { get set }
    
    /// The policy pointed to by the rule.
    var policy: String { get set }
    
    /// The comment for this rule.
    var comment: String? { get set }
    
    /// Rule evaluating function to determinse whether this rule match the given pattern.
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
        try container.encode("\(Self.schema),\(pattern),\(policy)\(comment != nil ? " // \(comment!)" : "")")
    }
}

extension Rule {
    
    public var description: String {
        "\(Self.schema) \(self.pattern) \(self.policy)"
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
        
        let schema = components.removeFirst().trimmingCharacters(in: .whitespaces)
        guard Self.schema == schema else {
            guard let canBeParsedAs = (supportedRules.first { $0.schema == schema }) else {
                throw ConfigurationSerializationError.failedToParseRule(reason: .unsupported)
            }
            throw ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(Self.self, butCanBeParsedAs: canBeParsedAs))
        }
        
        assert(supportedRules.contains(where: { $0.schema == schema }))
        self.init()
        
        pattern = components.removeFirst().trimmingCharacters(in: .whitespaces)
        components = components[0].components(separatedBy: "//")
        
        guard components.count >= 2 else {
            policy = components[0].trimmingCharacters(in: .whitespaces)
            return
        }
        policy = components.first!.trimmingCharacters(in: .whitespaces)
        comment = components[1].trimmingCharacters(in: .whitespaces)
    }
}

/// `RuleCollection` is a special rule that it's pattern is an URL of which external resources hosted.
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
        if let url = URL(string: pattern), url.isFileURL {
            return url
        }
        
        let filename = Insecure.SHA1.hash(data: Data(pattern.utf8))
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
    
    /// Load external resources from url resolved with pattern and a completion will invoke whenever success or failed.
    ///
    /// If pattern is file url or is not a valid url string thist will finished with `.invalidExteranlResources` error.
    /// else start downloading resources from that url and save downloaded file to `dstURL`,
    /// after that `reloadData()` will be call and completed with resolved standard rules.
    public func performLoadingExternalResources(completion: @escaping (Result<[Rule], Error>) -> Void) {
        guard shouldPerformDownloading else {
            self.reloadData()
            completion(.success(self.standardRules))
            return
        }
        
        guard let url = URL(string: pattern), !url.isFileURL else {
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
        lhs.pattern == rhs.pattern
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
        
        let schema = components.removeFirst().trimmingCharacters(in: .whitespaces)
        guard Self.schema == schema else {
            guard let canBeParsedAs = (supportedRules.first { $0.schema == schema }) else {
                throw ConfigurationSerializationError.failedToParseRule(reason: .unsupported)
            }
            throw ConfigurationSerializationError.failedToParseRule(reason: .failedToParseAs(Self.self, butCanBeParsedAs: canBeParsedAs))
        }
        
        assert(supportedRules.contains(where: { $0.schema == schema }))

        self.init()
        
        pattern = components.removeFirst().trimmingCharacters(in: .whitespaces)
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

/// `DomainRule` use domain as pattern and matches the full domain name when evaluating.
public struct DomainRule: Codable, Equatable, RulePrivate {
    
    public static let schema: String = "DOMAIN"
    
    public var pattern: String
    
    public var policy: String
    
    public var comment: String?
    
    fileprivate init() {
        self.pattern = "*"
        self.policy = "direct"
    }
    
    public func match(_ pattern: String) -> Bool {
        self.pattern == pattern
    }
}

/// `DomainSuffixRule` use domain suffix as pattern and matches the full domain name or suffix when evaluating.
public struct DomainSuffixRule: Codable, Equatable, RulePrivate {
    
    public static let schema: String = "DOMAIN-SUFFIX"
    
    public var pattern: String
    
    public var policy: String
    
    public var comment: String?
    
    fileprivate init() {
        self.pattern = "*"
        self.policy = "direct"
    }
    
    public func match(_ pattern: String) -> Bool {
        // e.g. apple.com should match *.apple.com and apple.com
        // should not match *apple.com.
        self.pattern == pattern || ".\(pattern)".hasSuffix(self.pattern)
    }
}

/// `DomainKeywordRule` use domain keyword as pattern and matches whether domain contains pattern when evaluating.
public struct DomainKeywordRule: Codable, Equatable, RulePrivate {
    
    public static let schema: String = "DOMAIN-KEYWORD"
    
    public var pattern: String
    
    public var policy: String
    
    public var comment: String?
    
    fileprivate init() {
        self.pattern = "*"
        self.policy = "direct"
    }
    
    public func match(_ pattern: String) -> Bool {
        pattern.contains(self.pattern)
    }
}

/// `DomainSet` rules contains a lot of `DomainSuffixRule` as it's external resources.
public struct DomainSet: Codable, Equatable, RuleCollectionPrivate {
    
    public static let schema: String = "DOMAIN-SET"
    
    public var pattern: String
    
    public var policy: String
    
    public var comment: String?
    
    @Protected private var _standardRules: [Rule] = []
    public var standardRules: [Rule] {
        _standardRules
    }
    
    fileprivate init() {
        pattern = "*"
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
                return try? DomainSuffixRule(stringLiteral: "\(DomainSuffixRule.schema),\(literal),\(policy)")
            }
    }
}

/// `GeoIPRule` use ip string as pattern and matches country ISO code search from `GeoLite2` when evaluating.
public struct GeoIPRule: Codable, Equatable, RulePrivate {
    
    public static let schema: String = "GEOIP"
    
    @Protected static var geo: MaxMindDB?
    
    public var pattern: String
    
    public var policy: String
    
    public var comment: String?
    
    fileprivate init() {
        pattern = "*"
        policy = "direct"
    }
    
    public func match(_ pattern: String) -> Bool {
        do {
            let dictionary = try GeoIPRule.geo?.lookup(ipAddress: pattern) as? [String : [String : Any]]
            let country = dictionary?["country"]
            let countryCode = country?["iso_code"] as? String
            return self.pattern == countryCode
        } catch {
            return false
        }
    }
}

public struct FinalRule: Codable, Equatable, RulePrivate {
    
    public static let schema: String = "FINAL"
    
    public var pattern: String
    
    public var policy: String
    
    public var comment: String?
    
    fileprivate init() {
        pattern = "dns-failed"
        policy = "direct"
    }
    
    public func match(_ pattern: String) -> Bool {
        true
    }
}

public struct RuleSet: Codable, Equatable, RuleCollectionPrivate {
    
    public static let schema: String = "RULE-SET"
    
    public var pattern: String
    
    public var policy: String
    
    public var comment: String?
    
    @Protected private var _standardRules: [Rule] = []
    public var standardRules: [Rule] {
        _standardRules
    }
    
    public var shouldPerformDownloading: Bool {
        return pattern != "SYSTEM" && pattern != "LAN"
    }
    
    fileprivate init() {
        pattern = "*"
        policy = "direct"
    }
    
    public func reloadData() {
        guard let data = try? Data(contentsOf: dstURL), let file = String(data: data, encoding: .utf8) else {
            // Builtin rule collection is not supported yet.
            guard pattern != "SYSTEM", pattern != "LAN" else {
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

/// A type-erased rule.
public struct AnyRule: Codable, Rule {
    
    public static let schema: String = "*"
    
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
    
    public init(stringLiteral: String) throws {
        switch stringLiteral.components(separatedBy: ",").first!.trimmingCharacters(in: .whitespaces) {
            case DomainRule.schema:
                self = .init(underlying: try DomainRule(stringLiteral: stringLiteral))
            case DomainSuffixRule.schema:
                self = .init(underlying: try DomainSuffixRule(stringLiteral: stringLiteral))
            case DomainKeywordRule.schema:
                self = .init(underlying: try DomainKeywordRule(stringLiteral: stringLiteral))
            case DomainSet.schema:
                self = .init(underlying: try DomainSet(stringLiteral: stringLiteral))
            case FinalRule.schema:
                self = .init(underlying: try FinalRule(stringLiteral: stringLiteral))
            case GeoIPRule.schema:
                self = .init(underlying: try GeoIPRule(stringLiteral: stringLiteral))
            case RuleSet.schema:
                self = .init(underlying: try RuleSet(stringLiteral: stringLiteral))
            default:
                throw ConfigurationSerializationError.failedToParseRule(reason: .unsupported)
        }
    }
    
    public func encode(to encoder: Encoder) throws {
        try underlying.encode(to: encoder)
    }
    
    public func match(_ pattern: String) -> Bool {
        underlying.match(pattern)
    }
}

extension AnyRule: CustomStringConvertible {
    
    public var description: String {
        underlying.description
    }
}

extension AnyRule: Equatable {
    
    public static func == (lhs: AnyRule, rhs: AnyRule) -> Bool {
        lhs.pattern == rhs.pattern
        && lhs.policy == rhs.policy
        && lhs.comment == rhs.comment
    }
}
