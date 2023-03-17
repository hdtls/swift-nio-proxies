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

@_exported import Logging

/// Basic settings object that defines behavior and polices for logging and proxy settings.
public struct BasicSettings: Sendable {

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

    /// Initialize an instance of `BasicSettings` with specified logLevel, dnsServers exceptions,
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

    /// Initialize an instance of `BasicSettings`.
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

/// Configuration for HTTPS traffic decraption with MitM attacks.
public struct ManInTheMiddleSettings: Sendable {

    /// A boolean value determinse whether ssl should skip server cerfitication verification. Default is false.
    public var skipCertificateVerification: Bool

    /// Hostnames that should perform MitM.
    public var hostnames: [String]

    /// Base64 encoded CA P12 bundle.
    public var base64EncodedP12String: String?

    /// Passphrase for P12 bundle.
    public var passphrase: String?

    /// Initialize an instance of `ManInTheMiddleSettings` with specified skipCertificateVerification, hostnames, base64EncodedP12String, passphrase.
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

    /// Initialize an instance of `ManInTheMiddleSettings`.
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
