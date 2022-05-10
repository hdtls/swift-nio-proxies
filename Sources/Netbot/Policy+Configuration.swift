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
import NetbotHTTP
import NetbotSOCKS
import NetbotSS
import NetbotVMESS

extension AnyPolicy {

    /// Policy configuration object.
    public struct Configuration {

        /// Proxy server address.
        public var serverAddress: String

        /// Proxy server port.
        public var port: Int

        /// Username for HTTP basic authentication and SOCKS5 username password authentication.
        public var username: String?

        /// Password for HTTP basic authentication and SOCKS5 username password authentication.
        public var password: String?

        /// A boolean value determinse whether HTTP proxy should prefer using CONNECT tunnel.
        public var prefererHttpTunneling: Bool

        /// A boolean value determinse whether SSL should skip certification verification.
        public var skipCertificateVerification: Bool

        /// SSL sni.
        public var sni: String?

        /// SSL certificate pinning.
        public var certificatePinning: String?

        private var algo: CryptoAlgorithm?

        /// Initialize an instance of `Configuration` object with specified serverAddress, port, username, password,
        /// prefererHttpTunneling, skipCertificationVerification, sni, certificatePinning and algorithm.
        public init(
            serverAddress: String,
            port: Int,
            username: String? = nil,
            password: String? = nil,
            prefererHttpTunneling: Bool = false,
            skipCertificateVerification: Bool = false,
            sni: String? = nil,
            certificatePinning: String? = nil,
            algorithm: CryptoAlgorithm? = nil
        ) {
            self.serverAddress = serverAddress
            self.port = port
            self.username = username
            self.password = password
            self.prefererHttpTunneling = prefererHttpTunneling
            self.skipCertificateVerification = skipCertificateVerification
            self.sni = sni
            self.certificatePinning = certificatePinning
            self.algo = algorithm
        }

        /// Initialize an instance of `Configuration`.
        ///
        /// Calling this method is equivalent to calling
        /// ```swift
        /// init(
        ///     serverAddress: "",
        ///     port: 8080,
        ///     username: nil,
        ///     password: nil,
        ///     prefererHttpTunneling: false,
        ///     skipCertificateVerification: false,
        ///     sni: nil,
        ///     certificatePinning: nil,
        ///     algorithm: nil
        /// )
        /// ```
        public init() {
            serverAddress = ""
            port = 8080
            prefererHttpTunneling = false
            skipCertificateVerification = false
        }
    }
}

extension AnyPolicy.Configuration: Codable {

    private enum CodingKeys: String, CodingKey {
        case serverAddress
        case port
        case username
        case password
        case prefererHttpTunneling
        case skipCertificateVerification
        case sni
        case certificatePinning
        case algo = "algorithm"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        serverAddress = try container.decode(String.self, forKey: .serverAddress)
        port = try container.decode(Int.self, forKey: .port)
        username = try container.decodeIfPresent(String.self, forKey: .username)
        password = try container.decodeIfPresent(String.self, forKey: .password)
        prefererHttpTunneling =
            try container.decodeIfPresent(Bool.self, forKey: .prefererHttpTunneling) ?? false
        skipCertificateVerification =
            try container.decodeIfPresent(Bool.self, forKey: .skipCertificateVerification) ?? false
        sni = try container.decodeIfPresent(String.self, forKey: .sni)
        certificatePinning = try container.decodeIfPresent(String.self, forKey: .certificatePinning)
        if let rawValue = try container.decodeIfPresent(String.self, forKey: .algo) {
            algo = .init(rawValue: rawValue)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(serverAddress, forKey: .serverAddress)
        try container.encode(port, forKey: .port)
        try container.encodeIfPresent(username, forKey: .username)
        try container.encodeIfPresent(password, forKey: .password)
        try container.encodeIfPresent(
            prefererHttpTunneling == true ? true : nil,
            forKey: .prefererHttpTunneling
        )
        try container.encodeIfPresent(
            skipCertificateVerification == true ? true : nil,
            forKey: .skipCertificateVerification
        )
        try container.encodeIfPresent(sni, forKey: .sni)
        try container.encodeIfPresent(certificatePinning, forKey: .certificatePinning)
        try container.encodeIfPresent(algo?.rawValue, forKey: .algo)
    }
}

extension AnyPolicy.Configuration: SocketConfigurationProtocol {}

extension AnyPolicy.Configuration: HTTPProxyConfigurationProtocol {}

extension AnyPolicy.Configuration: TLSConfigurationProtocol {}

extension AnyPolicy.Configuration: ShadowsocksConfigurationProtocol {

    /// Shadowsocks encryption algorithm.
    public var algorithm: CryptoAlgorithm {
        get { algo ?? .aes128Gcm }
        set { algo = newValue }
    }

    /// Shadowsocks encryption password.
    public var passwordReference: String {
        assert(password != nil, "Shadowsocks MUST provide password to secure connection.")
        return password ?? ""
    }
}

extension AnyPolicy.Configuration: SOCKS5ConfigurationProtocol {}

extension AnyPolicy.Configuration: VMESSConfigurationProtocol {

    /// VMESS user object.
    public var user: UUID {
        guard let uuidString = username, let uuid = UUID(uuidString: uuidString) else {
            assertionFailure("VMESS MUST provide valid UUID string as username.")
            return UUID()
        }
        return uuid
    }
}
