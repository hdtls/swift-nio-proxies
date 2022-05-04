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

/// Capable of being authenticated.
public protocol AuthenticationCredentialConvertible {}

public protocol Policy: ConnectionPoolSource {

    var name: String { get set }

    var destinationAddress: NetAddress? { get set }
}

public struct DirectPolicy: Policy {

    public var name: String = "DIRECT"

    public var destinationAddress: NetAddress?
}

public struct RejectPolicy: Policy {

    public var name: String = "REJECT"

    public var destinationAddress: NetAddress?
}

public struct RejectTinyGifPolicy: Policy {

    public var name: String = "REJECT-TINYGIF"

    public var destinationAddress: NetAddress?
}

public struct ShadowsocksPolicy: Policy {

    public var name: String

    public var configuration: SocketConfigurationProtocol & ShadowsocksConfigurationProtocol

    public var destinationAddress: NetAddress?
}

public struct SOCKS5Policy: Policy {

    public var name: String

    public var configuration: SocketConfigurationProtocol & SOCKS5ConfigurationProtocol

    public var destinationAddress: NetAddress?
}

public struct SOCKS5OverTLSPolicy: Policy {

    public var name: String

    public var configuration:
        SocketConfigurationProtocol & SOCKS5ConfigurationProtocol & TLSConfigurationProtocol

    public var destinationAddress: NetAddress?
}

public struct HTTPProxyPolicy: Policy {

    public var name: String

    public var configuration: SocketConfigurationProtocol & HTTPProxyConfigurationProtocol

    public var destinationAddress: NetAddress?
}

public struct HTTPSProxyPolicy: Policy {

    public var name: String

    public var configuration:
        SocketConfigurationProtocol & HTTPProxyConfigurationProtocol & TLSConfigurationProtocol

    public var destinationAddress: NetAddress?
}

public struct VMESSPolicy: Policy {

    public var name: String

    public var configuration: SocketConfigurationProtocol & VMESSConfigurationProtocol

    public var destinationAddress: NetAddress?
}
