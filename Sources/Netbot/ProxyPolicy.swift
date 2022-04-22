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
import NetbotSOCKS
import NetbotSS

public protocol SocketConfigurationProtocol {

    /// The server address may be hostname or IP address.
    var serverAddress: String { get set }

    /// The server port
    var port: Int { get set }
}

public protocol TLSConfigurationConvertible {

    func asTLSClientConfiguration() -> TLSConfiguration
}

/// Capable of being authenticated.
public protocol AuthenticationCredentialConvertible {}

public protocol Policy: ConnectionPoolSource {}

public struct NoopConfiguration: SocketConfigurationProtocol {

    public var serverAddress: String = ""

    public var port: Int = 0
}

extension NoopConfiguration: Codable {}

extension NoopConfiguration: Equatable {}

public struct DirectPolicy: Policy {

    public var configuration: NoopConfiguration = .init()

    public var destinationAddress: NetAddress?
}

public struct RejectPolicy: Policy {

    public var configuration: NoopConfiguration = .init()

    public var destinationAddress: NetAddress?
}

public struct RejectTinyGifPolicy: Policy {

    public var configuration: NoopConfiguration = .init()

    public var destinationAddress: NetAddress?
}

public struct ShadowsocksPolicy: Policy {

    public var configuration: SocketConfigurationProtocol & ShadowsocksConfigurationProtocol

    public var destinationAddress: NetAddress?
}

extension NetbotSS.CryptoAlgorithm: Codable {}

public struct SOCKS5Policy: Policy {

    public var configuration: SocketConfigurationProtocol & SOCKS5ConfigurationProtocol

    public var destinationAddress: NetAddress?
}

public struct SOCKS5OverTLSPolicy: Policy {

    public var configuration:
        SocketConfigurationProtocol & SOCKS5ConfigurationProtocol & TLSConfigurationConvertible

    public var destinationAddress: NetAddress?
}

public struct HTTPProxyPolicy: Policy {

    public var configuration: SocketConfigurationProtocol & HTTPProxyConfigurationProtocol

    public var destinationAddress: NetAddress?
}

public struct HTTPSProxyPolicy: Policy {

    public var configuration:
        SocketConfigurationProtocol & HTTPProxyConfigurationProtocol & TLSConfigurationConvertible

    public var destinationAddress: NetAddress?
}

public struct VMESSPolicy: Policy {

    public var configuration: SocketConfigurationProtocol & VMESSConfigurationProtocol

    public var destinationAddress: NetAddress?
}
