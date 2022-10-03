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
import MaxMindDB

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

public enum RuleType: String, CaseIterable {
    case domain = "DOMAIN"
    case domainSuffix = "DOMAIN-SUFFIX"
    case domainKeyword = "DOMAIN-KEYWORD"
    case domainSet = "DOMAIN-SET"
    case ruleSet = "RULE-SET"
    case geoIp = "GEOIP"
    case final = "FINAL"

    fileprivate var containsExternalResources: Bool {
        switch self {
            case .domainSet, .ruleSet:
                return true
            default:
                return false
        }
    }
}

#if swift(>=5.5) && canImport(_Concurrency)
extension RuleType: Sendable {}

/// `Rule` protocol define basic rule object protocol.
public protocol Rule: Sendable {

    /// Identifier for this rule.
    var id: UUID { get }

    /// The rule type.
    var type: RuleType { get }

    /// The expression fot this rule.
    ///
    /// If rule is collection expression is used to save external resources url string.
    var expression: String { get set }

    /// The policy pointed to by the rule.
    var policy: String { get set }

    /// The comment for this rule, if no comment return empty string.
    var comment: String { get set }

    /// Rule evaluating function to determinse whether this rule match the given expression.
    /// - Returns: True if match else false.
    func match(_ pattern: String) -> Bool

    /// Initialize an instance of `Rule` with specified string.
    init(string: String) throws
}
#else
/// `Rule` protocol define basic rule object protocol.
public protocol Rule {

    /// Identifier for this rule.
    var id: UUID { get }

    /// The rule type.
    var type: RuleType { get }

    /// The expression fot this rule.
    ///
    /// If rule is collection expression is used to save external resources url string.
    var expression: String { get set }

    /// The policy pointed to by the rule.
    var policy: String { get set }

    /// The comment for this rule, if no comment return empty string.
    var comment: String { get set }

    /// Rule evaluating function to determinse whether this rule match the given expression.
    /// - Returns: True if match else false.
    func match(_ pattern: String) -> Bool

    /// Initialize an instance of `Rule` with specified string.
    init(string: String) throws
}
#endif

public struct AnyRule: Rule, CustomStringConvertible {

    public var id: UUID = UUID()

    @Protected static var db: MaxMindDB?

    public var type: RuleType

    public var expression: String

    public var policy: String

    public var comment: String

    @Protected private var standardRules: [AnyRule] = []

    /// External resources storage url.
    public var dstURL: URL? {
        guard type == .domainSet || type == .ruleSet else {
            return nil
        }

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

    public var description: String {
        var literals = [type.rawValue, policy]
        if !expression.isEmpty {
            literals.insert(expression, at: 1)
        }
        return literals.joined(separator: " ")
    }

    /// Initialize an instance of `AnyRule` with specified type, expression, policy and comment.
    public init(type: RuleType, expression: String, policy: String, comment: String) {
        self.type = type
        self.expression = expression
        self.policy = policy
        self.comment = comment
    }

    /// Initialize an instance of `AnyRule` with default values..
    ///
    /// Calling this method is equivalent to calling `init(type:domain:expression:policy:comment:)`
    /// with `.domain` type empty expression `DIRECT` policy and empty comment.
    public init() {
        self.init(type: .domain, expression: "", policy: "DIRECT", comment: "")
    }

    public init(string: String) throws {
        // Rule definitions are comma-separated except comments, and comment are
        // always at the end of the rule and followed by //.
        //
        // Becase comments may contain commas, so we parse comments first.
        var components = string.components(separatedBy: ",")

        let rawValue = components.removeFirst().trimmingCharacters(in: .whitespaces)
        guard let type = RuleType(rawValue: rawValue) else {
            throw ProfileSerializationError.failedToParseRule(reason: .unsupported)
        }

        self.type = type

        let countOfRequiredFields = type == .final ? 1 : 2
        guard components.count >= countOfRequiredFields else {
            throw ProfileSerializationError.failedToParseRule(reason: .missingField)
        }

        if type != .final {
            expression = components.removeFirst().trimmingCharacters(in: .whitespaces)
        } else {
            expression = ""
        }

        components = components.joined(separator: ",").components(separatedBy: "//")
        if components.count > 1 {
            policy = components.removeFirst().trimmingCharacters(in: .whitespaces)
            comment = components.joined(separator: "//").trimmingCharacters(in: .whitespaces)
        } else {
            policy = components.removeFirst().trimmingCharacters(in: .whitespaces)
            comment = ""
        }

        reloadData()
    }

    public func match(_ pattern: String) -> Bool {
        switch type {
            case .domain:
                return expression == pattern
            case .domainSuffix:
                // e.g. apple.com should match *.apple.com and apple.com
                // should not match *apple.com.
                return expression == pattern || ".\(pattern)".hasSuffix(expression)
            case .domainKeyword:
                return pattern.contains(expression)
            case .domainSet, .ruleSet:
                return standardRules.first {
                    $0.match(pattern)
                } != nil
            case .geoIp:
                do {
                    let dictionary =
                        try AnyRule.db?.lookup(ipAddress: pattern) as? [String: [String: Any]]
                    let country = dictionary?["country"]
                    let countryCode = country?["iso_code"] as? String
                    return self.expression == countryCode
                } catch {
                    return false
                }
            case .final:
                return true
        }
    }

    /// Load external resources from url resolved with expression, throws errors when failed.
    ///
    /// If expression is not a valid url string loading will finished with `.invalidExteranlResources` error.
    /// else start downloading resources from that url and save downloaded file to `dstURL`.
    public func performExternalResourcesLoading() async throws {
        guard type.containsExternalResources, let dstURL = dstURL else {
            return
        }

        guard let url = URL(string: expression), !url.isFileURL else {
            throw ProfileSerializationError.failedToParseRule(
                reason: .invalidExternalResources
            )
        }

        let resources: (URL, URLResponse) = try await withCheckedThrowingContinuation {
            continuation in
            URLSession.shared.downloadTask(with: url) { dst, response, error in
                guard error == nil else {
                    continuation.resume(throwing: error!)
                    return
                }

                continuation.resume(returning: (dst!, response!))
            }.resume()
        }

        // Remove older file first if exists.
        if FileManager.default.fileExists(atPath: dstURL.path) {
            try FileManager.default.removeItem(at: dstURL)
        }
        try FileManager.default.moveItem(at: resources.0, to: dstURL)
    }

    /// Load external resources from url resolved with expression.
    /// - Parameter completion: The completion handler.
    public func performExternalResourcesLoading(completion: @escaping (Error?) -> Void) {
        guard type.containsExternalResources, let dstURL = dstURL else {
            completion(nil)
            return
        }

        guard let url = URL(string: expression), !url.isFileURL else {
            completion(
                ProfileSerializationError.failedToParseRule(reason: .invalidExternalResources)
            )
            return
        }

        URLSession.shared.downloadTask(with: url) { srcURL, response, error in
            guard error == nil else {
                completion(error!)
                return
            }

            guard let srcURL = srcURL else {
                completion(nil)
                return
            }

            do {
                // Remove older file first if exists.
                if FileManager.default.fileExists(atPath: dstURL.path) {
                    try FileManager.default.removeItem(at: dstURL)
                }
                try FileManager.default.moveItem(at: srcURL, to: dstURL)
                completion(nil)
            } catch {
                completion(error)
                assertionFailure(error.localizedDescription)
            }
        }.resume()
    }

    public mutating func reloadData() {
        switch type {
            case .domainSet:
                guard let dstURL = dstURL,
                    let data = try? Data(contentsOf: dstURL),
                    let file = String(data: data, encoding: .utf8)
                else {
                    return
                }
                standardRules = file.split(separator: "\n")
                    .compactMap {
                        let literal = $0.trimmingCharacters(in: .whitespaces)
                        guard !literal.isEmpty else {
                            return nil
                        }
                        return try? AnyRule(
                            string: "\(RuleType.domainSuffix.rawValue),\(literal),\(policy)"
                        )
                    }
            case .ruleSet:
                guard let dstURL = dstURL,
                    let data = try? Data(contentsOf: dstURL),
                    let file = String(data: data, encoding: .utf8)
                else {
                    return
                }
                standardRules = file.split(separator: "\n")
                    .compactMap {
                        let literal = $0.trimmingCharacters(in: .whitespaces)
                        guard !literal.isEmpty else {
                            return nil
                        }
                        return try? AnyRule(string: literal + ",\(policy)")
                    }
            default:
                break
        }
    }
}

extension AnyRule: Codable {

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        try self.init(string: container.decode(String.self))
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        var string =
            type == .final
            ? "\(type.rawValue),\(policy)" : "\(type.rawValue),\(expression),\(policy)"
        if !comment.isEmpty {
            string.append(" // \(comment)")
        }
        try container.encode(string)
    }
}

#if swift(>=5.5) && canImport(_Concurrency)
extension AnyRule: Sendable {}
#endif
