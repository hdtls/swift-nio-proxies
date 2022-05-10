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

import ConnectionPool
import EraseNilDecoding
import Foundation
import NIOSSL
import NetbotCore
import NetbotHTTP
import NetbotSOCKS
import NetbotSS
import NetbotVMESS

public protocol SocketConfigurationProtocol {

    /// The server address may be hostname or IP address.
    var serverAddress: String { get set }

    /// The server port
    var port: Int { get set }
}

public protocol TLSConfigurationProtocol {

    var skipCertificateVerification: Bool { get set }

    var sni: String? { get set }

    var certificatePinning: String? { get set }
}

/// Policy protocol representation a policy object.
public protocol Policy: ConnectionPoolSource {

    /// The name of the policy.
    var name: String { get set }

    /// Destination address.
    var destinationAddress: NetAddress? { get set }
}

/// DirectPolicy will tunnel connection derectly.
public struct DirectPolicy: Policy {

    public var name: String = "DIRECT"

    public var destinationAddress: NetAddress?
}

/// RejectPolicy will reject connection to the destination.
public struct RejectPolicy: Policy {

    public var name: String = "REJECT"

    public var destinationAddress: NetAddress?
}

/// RejectTinyGifPolicy will reject connection and response a tiny gif.
public struct RejectTinyGifPolicy: Policy {

    public var name: String = "REJECT-TINYGIF"

    public var destinationAddress: NetAddress?
}

/// HTTPProxyPolicy will tunning connection to the destination via HTTP proxy.
public struct HTTPProxyPolicy: Policy {

    public var name: String

    public var configuration: SocketConfigurationProtocol & HTTPProxyConfigurationProtocol

    public var destinationAddress: NetAddress?

    public init(
        name: String,
        configuration: SocketConfigurationProtocol & HTTPProxyConfigurationProtocol
    ) {
        self.name = name
        self.configuration = configuration
    }
}

/// HTTPSProxyPolicy will tunning connection to the destination via HTTPS proxy.
public struct HTTPSProxyPolicy: Policy {

    public var name: String

    public var configuration:
        SocketConfigurationProtocol & HTTPProxyConfigurationProtocol & TLSConfigurationProtocol

    public var destinationAddress: NetAddress?

    public init(
        name: String,
        configuration: SocketConfigurationProtocol & HTTPProxyConfigurationProtocol
            & TLSConfigurationProtocol
    ) {
        self.name = name
        self.configuration = configuration
    }
}

/// SOCKS5Policy will tunning connection to the destination via SOCKS5 proxy.
public struct SOCKS5Policy: Policy {

    public var name: String

    public var configuration: SocketConfigurationProtocol & SOCKS5ConfigurationProtocol

    public var destinationAddress: NetAddress?

    public init(
        name: String,
        configuration: SocketConfigurationProtocol & SOCKS5ConfigurationProtocol
    ) {
        self.name = name
        self.configuration = configuration
    }
}

/// SOCKS5OverTLSPolicy will tunning connection to the destination via SOCKS5 proxy.
public struct SOCKS5OverTLSPolicy: Policy {

    public var name: String

    public var configuration:
        SocketConfigurationProtocol & SOCKS5ConfigurationProtocol & TLSConfigurationProtocol

    public var destinationAddress: NetAddress?

    public init(
        name: String,
        configuration: SocketConfigurationProtocol & SOCKS5ConfigurationProtocol
            & TLSConfigurationProtocol
    ) {
        self.name = name
        self.configuration = configuration
    }
}

/// ShadowsocksPolicy will tunning connection to the destination via Shadowsocks proxy.
public struct ShadowsocksPolicy: Policy {

    public var name: String

    public var configuration: SocketConfigurationProtocol & ShadowsocksConfigurationProtocol

    public var destinationAddress: NetAddress?

    public init(
        name: String,
        configuration: SocketConfigurationProtocol & ShadowsocksConfigurationProtocol
    ) {
        self.name = name
        self.configuration = configuration
    }
}

/// VMESSPolicy will tunning connection to the destination via VMESS proxy.
public struct VMESSPolicy: Policy {

    public var name: String

    public var configuration: SocketConfigurationProtocol & VMESSConfigurationProtocol

    public var destinationAddress: NetAddress?

    public init(
        name: String,
        configuration: SocketConfigurationProtocol & VMESSConfigurationProtocol
    ) {
        self.name = name
        self.configuration = configuration
    }
}
