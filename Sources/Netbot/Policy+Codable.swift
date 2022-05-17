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
import NetbotCore

/// A type-erased policy value.
public struct AnyPolicy {

    /// Identifier for this policy.
    public var id: UUID = .init()

    /// The actual policy value.
    public internal(set) var base: Policy

    /// Initialize an instance of `AnyPolicy` with specified base value.
    public init<P>(_ base: P) where P: Policy {
        self.base = base
    }

    public init<P>(id: UUID = .init(), base: P) where P: Policy {
        self.id = id
        self.base = base
    }
}

extension AnyPolicy {

    /// Builtin policies.
    ///
    /// For current version this array contains three element `DirectPolicy`, `RejectPolicy` and `RejectTinyGifPolicy`.
    public static let builtin: [AnyPolicy] = [
        .init(DirectPolicy()),
        .init(RejectPolicy()),
        .init(RejectTinyGifPolicy()),
    ]
}

extension AnyPolicy: Codable {

    enum CodingKeys: String, CodingKey {
        case name
        case type
        case configuration
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        let name = try container.decode(String.self, forKey: .name)

        let rawValue = try container.decode(String.self, forKey: .type)

        switch rawValue {
            case "direct":
                base = DirectPolicy()
            case "reject":
                base = RejectPolicy()
            case "reject-tinygif":
                base = RejectTinyGifPolicy()
            case "http":
                let configuration = try container.decode(
                    AnyPolicy.Configuration.self,
                    forKey: .configuration
                )
                base = HTTPProxyPolicy(name: name, configuration: configuration)
            case "https":
                let configuration = try container.decode(
                    AnyPolicy.Configuration.self,
                    forKey: .configuration
                )
                base = HTTPSProxyPolicy(name: name, configuration: configuration)
            case "socks5":
                let configuration = try container.decode(
                    AnyPolicy.Configuration.self,
                    forKey: .configuration
                )
                base = SOCKS5Policy(name: name, configuration: configuration)
            case "socks5-over-tls":
                let configuration = try container.decode(
                    AnyPolicy.Configuration.self,
                    forKey: .configuration
                )
                base = SOCKS5OverTLSPolicy(name: name, configuration: configuration)
            case "ss":
                let configuration = try container.decode(
                    AnyPolicy.Configuration.self,
                    forKey: .configuration
                )
                base = ShadowsocksPolicy(name: name, configuration: configuration)
            case "vmess":
                let configuration = try container.decode(
                    AnyPolicy.Configuration.self,
                    forKey: .configuration
                )
                base = VMESSPolicy(name: name, configuration: configuration)
            default:
                throw ProfileSerializationError.invalidFile(reason: .dataCorrupted)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)

        try container.encode(base.name, forKey: .name)

        var configuration: AnyPolicy.Configuration?

        switch base {
            case is DirectPolicy:
                try container.encode("direct", forKey: .type)
            case is RejectPolicy:
                try container.encode("reject", forKey: .type)
            case is RejectTinyGifPolicy:
                try container.encode("reject-tinygif", forKey: .type)
            case let policy as HTTPProxyPolicy:
                try container.encode("http", forKey: .type)
                configuration = .init(
                    serverAddress: policy.configuration.serverAddress,
                    port: policy.configuration.port,
                    username: policy.configuration.username,
                    password: policy.configuration.password,
                    prefererHttpTunneling: policy.configuration.prefererHttpTunneling
                )
            case let policy as HTTPSProxyPolicy:
                try container.encode("https", forKey: .type)
                configuration = .init(
                    serverAddress: policy.configuration.serverAddress,
                    port: policy.configuration.port,
                    username: policy.configuration.username,
                    password: policy.configuration.password,
                    prefererHttpTunneling: policy.configuration.prefererHttpTunneling,
                    skipCertificateVerification: policy.configuration.skipCertificateVerification,
                    sni: policy.configuration.sni,
                    certificatePinning: policy.configuration.certificatePinning
                )
            case let policy as SOCKS5Policy:
                try container.encode("socks5", forKey: .type)
                configuration = .init(
                    serverAddress: policy.configuration.serverAddress,
                    port: policy.configuration.port,
                    username: policy.configuration.username,
                    password: policy.configuration.password
                )
            case let policy as SOCKS5OverTLSPolicy:
                try container.encode("socks5-over-tls", forKey: .type)
                configuration = .init(
                    serverAddress: policy.configuration.serverAddress,
                    port: policy.configuration.port,
                    username: policy.configuration.username,
                    password: policy.configuration.password,
                    skipCertificateVerification: policy.configuration.skipCertificateVerification,
                    sni: policy.configuration.sni,
                    certificatePinning: policy.configuration.certificatePinning
                )
            case let policy as ShadowsocksPolicy:
                try container.encode("ss", forKey: .type)
                configuration = .init(
                    serverAddress: policy.configuration.serverAddress,
                    port: policy.configuration.port,
                    password: policy.configuration.passwordReference,
                    algorithm: policy.configuration.algorithm
                )
            case let policy as VMESSPolicy:
                try container.encode("vmess", forKey: .type)
                configuration = .init(
                    serverAddress: policy.configuration.serverAddress,
                    port: policy.configuration.port,
                    username: policy.configuration.user.uuidString
                )
            default:
                fatalError("Unsupported policy \(base).")
        }

        try container.encodeIfPresent(configuration, forKey: .configuration)
    }
}
