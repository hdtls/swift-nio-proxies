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
import Logging

/// A profile object that defines behavior and policies for a Netbot process.
public struct Profile: Sendable {

    /// The rules contains in this configuration.
    public var rules: [ParsableRule]

    /// A configuration object that provides HTTP MitM configuration for this process.
    public var mitm: MitMConfiguration

    /// A configuration object that provides general configuration for this process.
    public var general: BasicConfiguration

    /// All proxy policy object contains in this configuration object.
    public var policies: [any Policy]

    /// All selectable policy groups contains in this configuration object.
    public var policyGroups: [PolicyGroup]

    /// Initialize an instance of `Profile` with the specified general, replicat, rules, mitm,
    /// polcies and policyGroups.
    public init(
        general: BasicConfiguration,
        rules: [ParsableRule],
        mitm: MitMConfiguration,
        policies: [any Policy],
        policyGroups: [PolicyGroup]
    ) {
        self.general = general
        self.rules = rules
        self.mitm = mitm
        self.policies = policies
        self.policyGroups = policyGroups
    }

    /// Initialize an `Profile`.
    ///
    /// Calling this method is equivalent to calling
    /// `init(general:rules:mitm:policies:policyGroups:)`
    /// with a default general, replica rules, mitm, policies and policyGroups object.
    public init() {
        self.init(
            general: .init(),
            rules: .init(),
            mitm: .init(),
            policies: .init(),
            policyGroups: .init()
        )
    }
}

extension Profile: Codable {

    enum CodingKeys: String, CodingKey {
        case rules
        case mitm
        case general
        case policies
        case policyGroups
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let ruleLiterals = try container.decodeIfPresent([String].self, forKey: .rules) ?? []
        self.rules = try ruleLiterals.map {
            var components = $0.split(separator: ",")
            let id = String(components.removeFirst())
            guard let factory = RuleSystem.factory(for: .init(rawValue: id)) else {
                throw ProfileSerializationError.failedToParseRule(reason: .unsupported)
            }
            try factory.validate($0)
            return factory.init($0)!
        }

        self.mitm =
            try container.decodeIfPresent(MitMConfiguration.self, forKey: .mitm) ?? .init()
        self.general =
            try container.decodeIfPresent(BasicConfiguration.self, forKey: .general) ?? .init()

        let policies = try container.decodeIfPresent([__Policy].self, forKey: .policies) ?? []
        self.policies = policies.map { $0.base }

        let policyGroups =
            try container.decodeIfPresent([__PolicyGroup].self, forKey: .policyGroups) ?? []

        let supportedPolicies = Builtin.policies + self.policies

        self.policyGroups = policyGroups.map {
            PolicyGroup(
                name: $0.name,
                policies: $0.policies.compactMap { policy in
                    supportedPolicies.first {
                        $0.name == policy
                    }
                }
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(
            rules.isEmpty ? nil : rules.map { $0.description },
            forKey: .rules
        )
        try container.encode(mitm, forKey: .mitm)
        try container.encode(general, forKey: .general)
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

/// Basic configuration object that defines behavior and polices for logging and proxy settings.
public struct BasicConfiguration: Codable, Equatable, Hashable, Sendable {

    /// Log level use for `Logging.Logger`.`
    public var logLevel: Logger.Level

    /// DNS servers use for system proxy.
    public var dnsServers: [String]

    /// Exceptions use for system proxy.
    public var exceptions: [String]

    /// Http listen address use for system http proxy.
    public var httpListenAddress: String?

    /// Http listen port use for system http proxy
    public var httpListenPort: Int?

    /// Socks listen address use for system socks proxy.
    public var socksListenAddress: String?

    /// Socks listen port use for system socks proxy.
    public var socksListenPort: Int?

    /// A boolean value that determines whether system proxy should exclude simple hostnames.
    public var excludeSimpleHostnames: Bool

    /// Initialize an instance of `BasicConfiguration` with specified logLevel, dnsServers exceptions,
    /// httpListenAddress, httpListenPort, socksListenAddress, socksListenPort and excludeSimpleHostnames.
    public init(
        logLevel: Logger.Level,
        dnsServers: [String],
        exceptions: [String],
        httpListenAddress: String?,
        httpListenPort: Int?,
        socksListenAddress: String?,
        socksListenPort: Int?,
        excludeSimpleHostnames: Bool
    ) {
        self.logLevel = logLevel
        self.dnsServers = dnsServers
        self.exceptions = exceptions
        self.httpListenAddress = httpListenAddress
        self.httpListenPort = httpListenPort
        self.socksListenAddress = socksListenAddress
        self.socksListenPort = socksListenPort
        self.excludeSimpleHostnames = excludeSimpleHostnames
    }

    /// Initialize an instance of `BasicConfiguration`.
    ///
    /// Calling this method is equivalent to calling `init(logLevel:dnsServers:exceptions:httpListenAddress:httpListenPort:socksListenAddress:socksListenPort:excludeSimpleHostnames:)`
    /// with `info` logLevel, `["system"]` dnsServers, `nil` exceptions, httpListenAddress, httpListenPort,
    /// socksListenAddress, socksListenPort and `false` excludeSimpleHostnames.
    public init() {
        self.init(
            logLevel: .info,
            dnsServers: ["system"],
            exceptions: [],
            httpListenAddress: nil,
            httpListenPort: nil,
            socksListenAddress: nil,
            socksListenPort: nil,
            excludeSimpleHostnames: false
        )
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.logLevel = try container.decodeIfPresent(Logger.Level.self, forKey: .logLevel) ?? .info
        self.dnsServers = try container.decodeIfPresent([String].self, forKey: .dnsServers) ?? []
        self.exceptions = try container.decodeIfPresent([String].self, forKey: .exceptions) ?? []
        self.httpListenAddress = try container.decodeIfPresent(
            String.self,
            forKey: .httpListenAddress
        )
        self.httpListenPort = try container.decodeIfPresent(Int.self, forKey: .httpListenPort)
        self.socksListenAddress = try container.decodeIfPresent(
            String.self,
            forKey: .socksListenAddress
        )
        self.socksListenPort = try container.decodeIfPresent(Int.self, forKey: .socksListenPort)
        self.excludeSimpleHostnames =
            try container.decodeIfPresent(Bool.self, forKey: .excludeSimpleHostnames) ?? false
    }

    enum CodingKeys: CodingKey {
        case logLevel
        case dnsServers
        case exceptions
        case httpListenAddress
        case httpListenPort
        case socksListenAddress
        case socksListenPort
        case excludeSimpleHostnames
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(self.logLevel, forKey: .logLevel)
        try container.encode(self.dnsServers, forKey: .dnsServers)
        try container.encode(self.exceptions, forKey: .exceptions)
        try container.encodeIfPresent(self.httpListenAddress, forKey: .httpListenAddress)
        try container.encodeIfPresent(self.httpListenPort, forKey: .httpListenPort)
        try container.encodeIfPresent(self.socksListenAddress, forKey: .socksListenAddress)
        try container.encodeIfPresent(self.socksListenPort, forKey: .socksListenPort)
        try container.encode(self.excludeSimpleHostnames, forKey: .excludeSimpleHostnames)
    }
}

/// Configuration for HTTPS traffic decraption with MitM attacks.
public struct MitMConfiguration: Codable, Equatable, Hashable, Sendable {

    /// A boolean value determinse whether ssl should skip server cerfitication verification.
    public var skipCertificateVerification: Bool

    /// Hostnames that should perform MitM.
    public var hostnames: [String]

    /// Base64 encoded CA P12 bundle.
    public var base64EncodedP12String: String?

    /// Passphrase for P12 bundle.
    public var passphrase: String?

    /// Initialize an instance of `Configuration` with specified skipCertificateVerification, hostnames, base64EncodedP12String, passphrase.
    /// - Parameters:
    ///   - skipCertificateVerification: A boolean value determinse whether client should skip server certificate verification.
    ///   - hostnames: Hostnames use when decript.
    ///   - base64EncodedP12String: The base64 encoded p12 certificate bundle string.
    ///   - passphrase: Passphrase for p12 bundle.
    public init(
        skipCertificateVerification: Bool,
        hostnames: [String],
        base64EncodedP12String: String?,
        passphrase: String?
    ) {
        self.skipCertificateVerification = skipCertificateVerification
        self.hostnames = hostnames
        self.passphrase = passphrase
        self.base64EncodedP12String = base64EncodedP12String
    }

    /// Initialize an instance of `Configuration`.
    ///
    /// Calling this method is equivalent to calling
    /// `init(skipCertificateVerification:hostnames:base64EncodedP12String:passphrase:)`
    /// with a default skipCertificateVerification, hostnames, base64EncodedP12String and passphrase values.
    public init() {
        self.init(
            skipCertificateVerification: false,
            hostnames: [],
            base64EncodedP12String: nil,
            passphrase: nil
        )
    }
}

/// Selectable policy group object that defines policy group and current selected policy.
public struct PolicyGroup: Sendable {

    public var id: UUID = .init()

    /// The name for this PolicyGroup.
    public var name: String

    /// Policies included in this policy group.
    public var policies: [any Policy]

    /// Initialize an instance of `PolicyGroup` with specified name and policies.
    public init(id: UUID = .init(), name: String, policies: [any Policy]) {
        self.id = id
        self.name = name
        self.policies = policies
    }
}

/// PolicyGroup coding wrapper.
struct __PolicyGroup: Codable {
    let name: String
    let policies: [String]

    enum CodingKeys: String, CodingKey {
        case name
        case policies
    }
}
