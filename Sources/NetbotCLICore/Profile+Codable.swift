//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2023 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

@_exported import NIONetbot

extension Profile: Codable {

    private enum CodingKeys: String, CodingKey {
        case rules
        case manInTheMiddleSettings
        case basicSettings
        case policies
        case policyGroups
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        let ruleLiterals = try container.decodeIfPresent([String].self, forKey: .rules) ?? []
        let rules = try ruleLiterals.map {
            var components = $0.split(separator: ",")
            let id = String(components.removeFirst())
            guard let factory = RuleSystem.factory(for: .init(rawValue: id)) else {
                throw ProfileSerializationError.failedToParseRule(reason: .unsupported)
            }
            try factory.validate($0)
            return factory.init($0)!
        }
        let manInTheMiddleSettings =
            try container.decodeIfPresent(
                ManInTheMiddleSettings.self, forKey: .manInTheMiddleSettings)
        let basicSettings =
            try container.decodeIfPresent(BasicSettings.self, forKey: .basicSettings)
        let policies = try container.decodeIfPresent([__Policy].self, forKey: .policies)?.map {
            $0.base
        }

        let policyGroups = try container.decodeIfPresent([PolicyGroup].self, forKey: .policyGroups)

        self.init(
            basicSettings: basicSettings ?? .init(),
            rules: rules,
            manInTheMiddleSettings: manInTheMiddleSettings ?? .init(),
            policies: policies ?? [],
            policyGroups: policyGroups ?? []
        )
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(
            rules.isEmpty ? nil : rules.map { $0.description },
            forKey: .rules
        )
        try container.encode(manInTheMiddleSettings, forKey: .manInTheMiddleSettings)
        try container.encode(basicSettings, forKey: .basicSettings)
        try container.encodeIfPresent(
            policies.isEmpty ? nil : policies.map(__Policy.init),
            forKey: .policies
        )
        try container.encodeIfPresent(
            policyGroups.isEmpty ? nil : policyGroups.map { $0.name },
            forKey: .policyGroups
        )
    }
}

/// PolicyGroup coding wrapper.
struct PolicyGroup: NIONetbot.PolicyGroup, Codable {
    var name: String
    var policies: [String]

    enum CodingKeys: String, CodingKey {
        case name
        case policies
    }
}
