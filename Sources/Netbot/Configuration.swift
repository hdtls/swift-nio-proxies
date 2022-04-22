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

/// A configuration object that defines behavior and policies for a Netbot process.
public struct Configuration: Codable {

    /// The rules contains in this configuration.
    @EraseNilToEmpty public var rules: [AnyRule]

    /// A configuration object that provides HTTP MitM configuration for this process.
    @EraseNilToEmpty public var mitm: MitMConfiguration

    /// A configuration object that provides general configuration for this process.
    @EraseNilToEmpty public var general: BasicConfiguration

    /// A configuration object that provides replica configuration for this process
    @EraseNilToEmpty public var replica: ReplicaConfiguration

    /// All proxy policy object contains in this configuration object.
    @EraseNilToEmpty public var policies: [AnyPolicy]

    /// All selectable policy groups contains in this configuration object.
    @EraseNilToEmpty public var policyGroups: [SelectablePolicyGroup]

    /// Initialize an instance of `Configuration` with the specified general, replicat, rules, mitm,
    /// polcies and policyGroups.
    public init(
        general: BasicConfiguration,
        replica: ReplicaConfiguration,
        rules: [AnyRule],
        mitm: MitMConfiguration,
        policies: [AnyPolicy],
        policyGroups: [SelectablePolicyGroup]
    ) {
        self.general = general
        self.replica = replica
        self.rules = rules
        self.mitm = mitm
        self.policies = policies
        self.policyGroups = policyGroups
    }

    /// Initialize an `Configuration`.
    ///
    /// Calling this method is equivalent to calling
    /// `init(general:replica:rules:mitm:policies:policyGroups:)`
    /// with a default general, replica rules, mitm, policies and policyGroups object.
    public init() {
        self.init(
            general: .init(),
            replica: .init(),
            rules: .init(),
            mitm: .init(),
            policies: .init(),
            policyGroups: .init()
        )
    }
}

/// Basic configuration object that defines behavior and polices for logging and proxy settings.
public struct BasicConfiguration: Codable, Equatable, EmptyInitializable {

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
    /// - Parameters:
    ///   - logLevel: see `logLevel` for `BasicConfiguration`.
    ///   - dnsServers: see `dnsServers` for `BasicConfiguration`.
    ///   - exceptions: see `exceptions` for `BasicConfiguration`.
    ///   - httpListenAddress: see `httpListenAddress` for `BasicConfiguration`.
    ///   - httpListenPort: see `httpListenPort` for `BasicConfiguration`.
    ///   - socksListenAddress: see `socksListenAddress` for `BasicConfiguration`.
    ///   - socksListenPort: see `socksListenPort` for `BasicConfiguration`.
    ///   - excludeSimpleHostnames: see `excludeSimpleHostnames` for `BasicConfiguration`.
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

/// Replica configuration object that defines behavior and filters.
public struct ReplicaConfiguration: Codable, Equatable, EmptyInitializable {

    /// A boolean value that determines whether to hide requests came from Apple.
    @EraseNilToTrue public var hideAppleRequests: Bool

    /// A boolean value that determines whether to hide requests came from Crashlytics.
    @EraseNilToTrue public var hideCrashlyticsRequests: Bool

    /// A boolean value that determines whether to hide requests came from CrashReporter.
    @EraseNilToTrue public var hideCrashReporterRequests: Bool

    /// A boolean value that determines whether to hide UDP requests.
    @EraseNilToFalse public var hideUdp: Bool

    /// The request message filter type.
    public var reqMsgFilterType: String?

    /// The request message filter.
    public var reqMsgFilter: String?

    /// Initialize an instance of `ReplicaConfiguration` with specified hideAppleRequests,
    /// hideCrashlyticsRequests, hideCrashReporterRequests, hideUDP, reqMsgFilterType and reqMsgFilter.
    public init(
        hideAppleRequests: Bool,
        hideCrashlyticsRequests: Bool,
        hideCrashReporterRequests: Bool,
        hideUdp: Bool,
        reqMsgFilterType: String?,
        reqMsgFilter: String?
    ) {
        self.hideAppleRequests = hideAppleRequests
        self.hideCrashlyticsRequests = hideCrashlyticsRequests
        self.hideCrashReporterRequests = hideCrashReporterRequests
        self.hideUdp = hideUdp
        self.reqMsgFilterType = reqMsgFilterType
        self.reqMsgFilter = reqMsgFilter
    }

    /// Initialzie an instance of `ReplicaConfiguration`.
    ///
    /// Calling this method is equivalent to calling
    /// `init(hideAppleRequests:hideCrashlyticsRequests:hideCrashReporterRequests:hideUDP:reqMsgFilterType:reqMsgFilter:)`
    /// with `true` hideAppleRequests, hideCrashlyticsRequests. hideCrashReporterRequests, `false` hideUdp
    /// and `nil` reqMsgFilterType, reqMsgFilter.
    public init() {
        self.init(
            hideAppleRequests: true,
            hideCrashlyticsRequests: true,
            hideCrashReporterRequests: true,
            hideUdp: false,
            reqMsgFilterType: nil,
            reqMsgFilter: nil
        )
    }
}

/// Selectable policy group object that defines policy group and current selected policy.
public struct SelectablePolicyGroup: Codable, Equatable {

    /// The name for this PolicyGroup.
    public var name: String

    /// Policies included in this policy group.
    public var policies: [String]

    /// Current selected policy.
    public var selected: String?

    enum CodingKeys: String, CodingKey {
        case name
        case policies
    }

    /// Initialize an instance of `SelectablePolicyGroup` with specified name and policies.
    public init(name: String, policies: [String]) {
        precondition(!policies.isEmpty, "You must provide at least one policy.")

        self.name = name
        self.policies = policies
    }
}

extension MitMConfiguration: EmptyInitializable {}
