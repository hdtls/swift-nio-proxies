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

import Logging
import NIONetbot

extension BasicSettings: Codable {

    private enum CodingKeys: CodingKey {
        case logLevel
        case dnsServers
        case exceptions
        case httpListenAddress
        case httpListenPort
        case socksListenAddress
        case socksListenPort
        case excludeSimpleHostnames
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let logLevel = try container.decodeIfPresent(Logger.Level.self, forKey: .logLevel)
        let dnsServers = try container.decodeIfPresent([String].self, forKey: .dnsServers)
        let exceptions = try container.decodeIfPresent([String].self, forKey: .exceptions)
        let httpListenAddress = try container.decodeIfPresent(
            String.self,
            forKey: .httpListenAddress
        )
        let httpListenPort = try container.decodeIfPresent(Int.self, forKey: .httpListenPort)
        let socksListenAddress = try container.decodeIfPresent(
            String.self,
            forKey: .socksListenAddress
        )
        let socksListenPort = try container.decodeIfPresent(Int.self, forKey: .socksListenPort)
        let excludeSimpleHostnames =
            try container.decodeIfPresent(Bool.self, forKey: .excludeSimpleHostnames)

        self.init(
            logLevel: logLevel ?? .info,
            dnsServers: dnsServers ?? [],
            exceptions: exceptions ?? [],
            httpListenAddress: httpListenAddress,
            httpListenPort: httpListenPort,
            socksListenAddress: socksListenAddress,
            socksListenPort: socksListenPort,
            excludeSimpleHostnames: excludeSimpleHostnames ?? false
        )
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

extension BasicSettings: Equatable {

    public static func == (lhs: BasicSettings, rhs: BasicSettings) -> Bool {
        lhs.logLevel == rhs.logLevel
            && lhs.dnsServers == rhs.dnsServers
            && lhs.exceptions == rhs.exceptions
            && lhs.httpListenAddress == rhs.httpListenAddress
            && lhs.httpListenPort == rhs.httpListenPort
            && lhs.socksListenAddress == rhs.socksListenAddress
            && lhs.socksListenPort == rhs.socksListenPort
            && lhs.excludeSimpleHostnames == rhs.excludeSimpleHostnames
    }
}

extension ManInTheMiddleSettings: Codable {

    private enum CodingKeys: CodingKey {
        case skipCertificateVerification
        case hostnames
        case base64EncodedP12String
        case passphrase
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let skipCertificateVerification = try container.decodeIfPresent(
            Bool.self,
            forKey: .skipCertificateVerification
        )
        let hostnames = try container.decodeIfPresent([String].self, forKey: .hostnames)
        let base64EncodedP12String = try container.decodeIfPresent(
            String.self,
            forKey: .base64EncodedP12String
        )
        let passphrase = try container.decodeIfPresent(String.self, forKey: .passphrase)

        self.init(
            skipCertificateVerification: skipCertificateVerification ?? false,
            hostnames: hostnames ?? [],
            base64EncodedP12String: base64EncodedP12String,
            passphrase: passphrase
        )
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(self.skipCertificateVerification, forKey: .skipCertificateVerification)
        try container.encode(self.hostnames, forKey: .hostnames)
        try container.encodeIfPresent(self.base64EncodedP12String, forKey: .base64EncodedP12String)
        try container.encodeIfPresent(self.passphrase, forKey: .passphrase)
    }
}

extension ManInTheMiddleSettings: Equatable {

    public static func == (lhs: ManInTheMiddleSettings, rhs: ManInTheMiddleSettings) -> Bool {
        lhs.skipCertificateVerification == rhs.skipCertificateVerification
            && lhs.hostnames == rhs.hostnames
            && lhs.base64EncodedP12String == rhs.base64EncodedP12String
            && lhs.passphrase == rhs.passphrase
    }
}
