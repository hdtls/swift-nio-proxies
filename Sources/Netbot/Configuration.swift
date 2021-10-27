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
import HTTP
import Logging

public struct Configuration: Codable {
    
    public var rules: [AnyRule]
    public var mitm: MitMConfiguration
    public var general: BasicConfiguration
    public var replica: ReplicaConfiguration
    public var policies: [ProxyPolicy]
    public var selectablePolicyGroups: [SelectablePolicyGroup]
    
    enum CodingKeys: String, CodingKey {
        case rules = "[Rule]"
        case mitm = "[MitM]"
        case general = "[General]"
        case replica = "[Replica]"
        case policies = "[Proxy Policy]"
        case selectablePolicyGroups = "[Policy Group]"
    }
    
    public init(general: BasicConfiguration = .init(),
                replica: ReplicaConfiguration = .init(),
                rules: [AnyRule] = .init(),
                mitm: MitMConfiguration = .init(),
                policies: [ProxyPolicy] = .init(),
                selectablePolicyGroups: [SelectablePolicyGroup] = .init()) {
        self.general = general
        self.replica = replica
        self.rules = rules
        self.mitm = mitm
        self.policies = policies
        self.selectablePolicyGroups = selectablePolicyGroups
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        rules = try container.decodeIfPresent([AnyRule].self, forKey: .rules) ?? .init()
        mitm = try container.decodeIfPresent(MitMConfiguration.self, forKey: .mitm) ?? .init()
        general = try container.decodeIfPresent(BasicConfiguration.self, forKey: .general) ?? .init()
        replica = try container.decodeIfPresent(ReplicaConfiguration.self, forKey: .replica) ?? .init()
        policies = try container.decodeIfPresent([ProxyPolicy].self, forKey: .policies) ?? .init()
        selectablePolicyGroups = try container.decodeIfPresent([SelectablePolicyGroup].self, forKey: .selectablePolicyGroups) ?? .init()
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(rules, forKey: .rules)
        try container.encode(mitm, forKey: .mitm)
        try container.encode(general, forKey: .general)
        try container.encode(replica, forKey: .replica)
        try container.encodeIfPresent(policies.isEmpty ? nil : policies, forKey: .policies)
        try container.encodeIfPresent(selectablePolicyGroups.isEmpty ? nil : selectablePolicyGroups, forKey: .selectablePolicyGroups)
    }
}

public struct BasicConfiguration: Codable, Equatable {
    
    public var logLevel: Logger.Level
    public var dnsServers: [String]
    public var exceptions: [String]?
    public var httpListenAddress: String?
    public var httpListenPort: Int?
    public var socksListenAddress: String?
    public var socksListenPort: Int?
    public var excludeSimpleHostnames: Bool
    
    enum CodingKeys: String, CodingKey {
        case logLevel = "log-level"
        case dnsServers = "dns-servers"
        case exceptions = "exceptions"
        case httpListenAddress = "http-listen-address"
        case httpListenPort = "http-listen-port"
        case socksListenAddress = "socks-listen-address"
        case socksListenPort = "socks-listen-port"
        case excludeSimpleHostnames = "exclude-simple-hostnames"
    }
    
    public init(logLevel: Logger.Level = .info,
                dnsServers: [String] = ["system"],
                exceptions: [String]? = nil,
                httpListenAddress: String? = nil,
                httpListenPort: Int? = nil,
                socksListenAddress: String? = nil,
                socksListenPort: Int? = nil,
                excludeSimpleHostnames: Bool = false) {
        self.logLevel = logLevel
        self.dnsServers = dnsServers
        self.exceptions = exceptions
        self.httpListenAddress = httpListenAddress
        self.httpListenPort = httpListenPort
        self.socksListenAddress = socksListenAddress
        self.socksListenPort = socksListenPort
        self.excludeSimpleHostnames = excludeSimpleHostnames
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        logLevel = try container.decodeIfPresent(Logger.Level.self, forKey: .logLevel) ?? .info
        dnsServers = try container.decodeIfPresent(String.self, forKey: .dnsServers)?.split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces ) } ?? ["system"]
        exceptions = try container.decodeIfPresent(String.self, forKey: .exceptions)?.split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces ) }
        httpListenAddress = try container.decodeIfPresent(String.self, forKey: .httpListenAddress)
        httpListenPort = Int(try container.decodeIfPresent(String.self, forKey: .httpListenPort) ?? "")
        socksListenAddress = try container.decodeIfPresent(String.self, forKey: .socksListenAddress)
        socksListenPort = Int(try container.decodeIfPresent(String.self, forKey: .socksListenPort) ?? "")
        excludeSimpleHostnames = try container.decodeIfPresent(Bool.self, forKey: .excludeSimpleHostnames) ?? false
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(logLevel, forKey: .logLevel)
        try container.encode(dnsServers.joined(separator: ", "), forKey: .dnsServers)
        try container.encodeIfPresent(exceptions?.joined(separator: ", "), forKey: .exceptions)
        try container.encodeIfPresent(httpListenAddress, forKey: .httpListenAddress)
        try container.encodeIfPresent(httpListenPort != nil ? "\(httpListenPort!)" : nil, forKey: .httpListenPort)
        try container.encodeIfPresent(socksListenAddress, forKey: .socksListenAddress)
        try container.encodeIfPresent(socksListenPort != nil ? "\(socksListenPort!)" : nil, forKey: .socksListenPort)
        try container.encodeIfPresent(excludeSimpleHostnames, forKey: .excludeSimpleHostnames)
    }
}

public struct ReplicaConfiguration: Codable, Equatable {
    
    public var hideAppleRequests: Bool
    public var hideCrashlyticsRequests: Bool
    public var hideCrashReporterRequests: Bool
    public var hideUDP: Bool
    public var reqMsgFilterType: String?
    public var reqMsgFilter: String?
    
    enum CodingKeys: String, CodingKey {
        case hideAppleRequests = "hide-apple-requests"
        case hideCrashlyticsRequests = "hide-crashlytics-requests"
        case hideCrashReporterRequests = "hide-crash-reporter-requests"
        case hideUDP = "hide-udp"
        case reqMsgFilterType = "req-msg-filter-type"
        case reqMsgFilter = "req-msg-filter"
    }
    
    public init(hideAppleRequests: Bool = false,
                hideCrashlyticsRequests: Bool = false,
                hideCrashReporterRequests: Bool = false,
                hideUDP: Bool = false,
                reqMsgFilterType: String? = nil,
                reqMsgFilter: String? = nil) {
        self.hideAppleRequests = hideAppleRequests
        self.hideCrashlyticsRequests = hideCrashlyticsRequests
        self.hideCrashReporterRequests = hideCrashReporterRequests
        self.hideUDP = hideUDP
        self.reqMsgFilterType = reqMsgFilterType
        self.reqMsgFilter = reqMsgFilter
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        hideAppleRequests = try container.decodeIfPresent(Bool.self, forKey: .hideAppleRequests) ?? false
        hideCrashlyticsRequests = try container.decodeIfPresent(Bool.self, forKey: .hideCrashlyticsRequests) ?? false
        hideCrashReporterRequests = try container.decodeIfPresent(Bool.self, forKey: .hideCrashReporterRequests) ?? false
        hideUDP = try container.decodeIfPresent(Bool.self, forKey: .hideUDP) ?? false
        reqMsgFilter = try container.decodeIfPresent(String.self, forKey: .reqMsgFilter)
        reqMsgFilterType = try container.decodeIfPresent(String.self, forKey: .reqMsgFilterType)
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(hideAppleRequests, forKey: .hideAppleRequests)
        try container.encode(hideCrashlyticsRequests, forKey: .hideCrashlyticsRequests)
        try container.encode(hideCrashReporterRequests, forKey: .hideCrashReporterRequests)
        try container.encode(hideUDP, forKey: .hideUDP)
        try container.encodeIfPresent(reqMsgFilter, forKey: .reqMsgFilter)
        try container.encodeIfPresent(reqMsgFilterType, forKey: .reqMsgFilterType)
    }
}

public struct SelectablePolicyGroup: Codable, Equatable {
    
    public var name: String
    public var policies: [String]
    public var selected: String
    
    enum CodingKeys: String, CodingKey {
        case name
        case policies
    }
    
    public init(name: String, policies: [String]) {
        precondition(!policies.isEmpty, "You must provide at least one policy.")
        
        self.name = name
        self.policies = policies
        self.selected = policies.first!
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        name = try container.decode(String.self, forKey: .name)
        policies = try container.decode(String.self, forKey: .policies)
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { $0 != "select" }
        selected = policies.first!
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(name, forKey: .name)
        try container.encode("select, " + policies.joined(separator: ", "), forKey: .policies)
    }
}
