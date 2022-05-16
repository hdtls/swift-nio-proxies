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

import EraseNilDecoding
import Foundation
import Logging
import NetbotHTTP

/// A profile object that defines behavior and policies for a Netbot process.
public struct Profile: Codable {

    /// The rules contains in this configuration.
    @EraseNilToEmpty public var rules: [AnyRule]

    /// A configuration object that provides HTTP MitM configuration for this process.
    @EraseNilToEmpty public var mitm: MitMConfiguration

    /// A configuration object that provides general configuration for this process.
    @EraseNilToEmpty public var general: BasicConfiguration

    /// All proxy policy object contains in this configuration object.
    @EraseNilToEmpty public var policies: [AnyPolicy]

    /// All selectable policy groups contains in this configuration object.
    @EraseNilToEmpty public var policyGroups: [PolicyGroup]

    /// Initialize an instance of `Profile` with the specified general, replicat, rules, mitm,
    /// polcies and policyGroups.
    public init(
        general: BasicConfiguration,
        rules: [AnyRule],
        mitm: MitMConfiguration,
        policies: [AnyPolicy],
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

/// Basic configuration object that defines behavior and polices for logging and proxy settings.
public struct BasicConfiguration: Codable, EmptyInitializable {

    /// Log level use for `Logging.Logger`.`
    public var logLevel: Logger.Level

    /// DNS servers use for system proxy.
    @EraseNilToEmpty public var dnsServers: [String]

    /// Exceptions use for system proxy.
    @EraseNilToEmpty public var exceptions: [String]

    /// Http listen address use for system http proxy.
    public var httpListenAddress: String?

    /// Http listen port use for system http proxy
    public var httpListenPort: Int?

    /// Socks listen address use for system socks proxy.
    public var socksListenAddress: String?

    /// Socks listen port use for system socks proxy.
    public var socksListenPort: Int?

    /// A boolean value that determines whether system proxy should exclude simple hostnames.
    @EraseNilToTrue public var excludeSimpleHostnames: Bool

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
}

/// Selectable policy group object that defines policy group and current selected policy.
public struct PolicyGroup: Codable {

    public var id: UUID = .init()

    /// The name for this PolicyGroup.
    public var name: String

    /// Policies included in this policy group.
    public var policies: [String]

    private enum CodingKeys: String, CodingKey {
        case name
        case policies
    }

    /// Initialize an instance of `PolicyGroup` with specified name and policies.
    public init(name: String, policies: [String]) {
        precondition(!policies.isEmpty, "You must provide at least one policy.")

        self.name = name
        self.policies = policies
    }
}

extension MitMConfiguration: EmptyInitializable {}
