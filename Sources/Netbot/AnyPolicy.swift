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

public enum ProxyProtocol: String, CaseIterable, Equatable {

    case http = "HTTP"

    case https = "HTTPS"

    case socks5 = "SOCKS5"

    case socks5OverTLS = "SOCKS over TLS"

    case shadowsocks = "Shadowsocks"

    case vmess = "VMESS"

    public init?(rawValue: String) {
        switch rawValue {
            case "HTTP", "http":
                self = .http
            case "HTTPS", "https":
                self = .https
            case "SOCKS5", "socks5":
                self = .socks5
            case "SOCKS5 over TLS", "socks5 over tls", "socks5-tls":
                self = .socks5OverTLS
            case "Shadowsocks", "shadowsocks", "SS", "ss":
                self = .shadowsocks
            case "VMESS", "vmess":
                self = .vmess
            default:
                return nil
        }
    }
}

public enum PolicyType: Equatable {

    case direct

    case reject

    case rejectTinyGif

    case proxy(via: ProxyProtocol)
}

public protocol PolicyConvertible {

    func asPolicy() throws -> Policy
}

public struct AnyPolicy {

    public var id: UUID = UUID()

    public var name: String

    public var type: PolicyType

    public var configuration: ProxyConfiguration

    public var destinationAddress: NetAddress?
}

extension AnyPolicy {

    public static let direct: AnyPolicy = .init(
        name: "DIRECT",
        type: .direct,
        configuration: .init()
    )

    public static let reject: AnyPolicy = .init(
        name: "REJECT",
        type: .reject,
        configuration: .init()
    )

    public static let rejectTinyGif: AnyPolicy = .init(
        name: "REJECT-TINYGIF",
        type: .rejectTinyGif,
        configuration: .init()
    )

    public static let builtin: [AnyPolicy] = [.direct, .reject, .rejectTinyGif]
}

extension AnyPolicy: Codable {

    enum CodingKeys: String, CodingKey {
        case name
        case type
        case configuration
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        let rawValue = try container.decode(String.self, forKey: .type)
        switch rawValue {
            case "DIRECT", "direct":
                self = .direct
                return
            case "REJECT", "reject":
                self = .reject
                return
            case "REJECT-TINYGIF", "reject-tinygif":
                self = .rejectTinyGif
                return
            default:
                guard let `protocol` = ProxyProtocol.init(rawValue: rawValue) else {
                    throw ConfigurationSerializationError.invalidFile(reason: .dataCorrupted)
                }
                type = .proxy(via: `protocol`)
        }

        name = try container.decode(String.self, forKey: .name)
        configuration = try container.decode(ProxyConfiguration.self, forKey: .configuration)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)

        try container.encode(name, forKey: .name)
        try container.encode(configuration, forKey: .configuration)
        switch type {
            case .direct:
                try container.encode("direct", forKey: .type)
            case .reject:
                try container.encode("reject", forKey: .type)
            case .rejectTinyGif:
                try container.encode("reject-tinygif", forKey: .type)
            case .proxy(via: let `protocol`):
                try container.encode(`protocol`.rawValue, forKey: .type)
        }
        try container.encode(configuration, forKey: .configuration)
    }
}

extension AnyPolicy: PolicyConvertible {

    public func asPolicy() throws -> Policy {
        switch type {
            case .direct:
                return DirectPolicy(destinationAddress: destinationAddress)
            case .reject:
                return DirectPolicy(destinationAddress: destinationAddress)
            case .rejectTinyGif:
                return RejectTinyGifPolicy(destinationAddress: destinationAddress)
            case .proxy(via: let `protocol`):
                switch `protocol` {
                    case .http:
                        return HTTPProxyPolicy(
                            configuration: configuration,
                            destinationAddress: destinationAddress
                        )
                    case .https:
                        return HTTPSProxyPolicy(
                            configuration: configuration,
                            destinationAddress: destinationAddress
                        )
                    case .socks5:
                        return SOCKS5Policy(
                            configuration: configuration,
                            destinationAddress: destinationAddress
                        )
                    case .socks5OverTLS:
                        return SOCKS5OverTLSPolicy(
                            configuration: configuration,
                            destinationAddress: destinationAddress
                        )
                    case .shadowsocks:
                        return ShadowsocksPolicy(
                            configuration: configuration,
                            destinationAddress: destinationAddress
                        )
                    case .vmess:
                        return VMESSPolicy(
                            configuration: configuration,
                            destinationAddress: destinationAddress
                        )
                }
        }
    }
}
