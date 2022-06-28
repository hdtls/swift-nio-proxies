//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2022 Junfeng Zhang. and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation

public struct Proxy: Codable {

    public enum `Protocol`: String, CaseIterable, Codable, CustomStringConvertible {
        case http
        case socks5
        case shadowsocks = "ss"
        case vmess

        public var description: String {
            switch self {
                case .http:
                    return "HTTP"
                case .socks5:
                    return "SOCKS5"
                case .shadowsocks:
                    return "Shadowsocks"
                case .vmess:
                    return "VMESS"
            }
        }
    }

    /// Proxy server address.
    public var serverAddress: String

    /// Proxy server port.
    public var port: Int

    public var `protocol`: `Protocol`

    /// Username for proxy authentication.
    ///
    /// - note: For VMESS protocol username *MUST* be an UUID string.
    public var username: String

    /// Password for HTTP basic authentication and SOCKS5 username password authentication.
    public var password: String
    public var passwordReference: String { password }

    /// A boolean value determinse whether connection should perform username password authentication.
    ///
    /// - note: This is used in HTTP/HTTPS basic authentication and SOCKS/SOCKS over TLS username/password authentication.
    public var authenticationRequired: Bool

    /// A boolean value determinse whether HTTP proxy should prefer using CONNECT tunnel.
    public var prefererHttpTunneling: Bool

    /// A boolean value determinse whether connection should enable TLS.
    public var overTls: Bool

    /// A boolean value determinse whether SSL should skip certification verification.
    public var skipCertificateVerification: Bool

    /// SSL sni.
    public var sni: String

    /// SSL certificate pinning.
    public var certificatePinning: String

    /// SS encryption and decryption algorithm.
    ///
    /// - note: This is used in Shadowsocks protocol.
    public var algorithm: CryptoAlgorithm

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.serverAddress = try container.decode(String.self, forKey: .serverAddress)
        self.port = try container.decode(Int.self, forKey: .port)
        self.protocol = try container.decode(`Protocol`.self, forKey: .protocol)
        self.username = try container.decodeIfPresent(String.self, forKey: .username) ?? ""
        self.password = try container.decodeIfPresent(String.self, forKey: .password) ?? ""
        self.authenticationRequired =
            try container.decodeIfPresent(Bool.self, forKey: .authenticationRequired) ?? false
        self.prefererHttpTunneling =
            try container.decodeIfPresent(Bool.self, forKey: .prefererHttpTunneling) ?? false
        self.skipCertificateVerification =
            try container.decodeIfPresent(Bool.self, forKey: .skipCertificateVerification) ?? false
        self.sni = try container.decodeIfPresent(String.self, forKey: .sni) ?? ""
        self.certificatePinning =
            try container.decodeIfPresent(String.self, forKey: .certificatePinning) ?? ""
        self.algorithm =
            try container.decodeIfPresent(CryptoAlgorithm.self, forKey: .algorithm) ?? .aes128Gcm
        self.overTls = try container.decodeIfPresent(Bool.self, forKey: .overTls) ?? false
    }

    enum CodingKeys: CodingKey {
        case serverAddress
        case port
        case `protocol`
        case username
        case password
        case authenticationRequired
        case prefererHttpTunneling
        case skipCertificateVerification
        case sni
        case certificatePinning
        case algorithm
        case overTls
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(self.serverAddress, forKey: .serverAddress)
        try container.encode(self.port, forKey: .port)
        try container.encode(self.protocol, forKey: .protocol)
        try container.encodeIfPresent(
            self.username.isEmpty ? nil : self.username,
            forKey: .username
        )
        try container.encodeIfPresent(
            self.password.isEmpty ? nil : self.password,
            forKey: .password
        )
        try container.encodeIfPresent(
            self.authenticationRequired ? self.authenticationRequired : nil,
            forKey: .authenticationRequired
        )
        try container.encodeIfPresent(
            self.prefererHttpTunneling ? self.prefererHttpTunneling : nil,
            forKey: .prefererHttpTunneling
        )
        try container.encodeIfPresent(
            self.skipCertificateVerification ? self.skipCertificateVerification : nil,
            forKey: .skipCertificateVerification
        )
        try container.encodeIfPresent(self.sni.isEmpty ? nil : self.sni, forKey: .sni)
        try container.encodeIfPresent(
            self.certificatePinning.isEmpty ? nil : self.certificatePinning,
            forKey: .certificatePinning
        )
        try container.encodeIfPresent(
            self.algorithm != .aes128Gcm ? self.algorithm : nil,
            forKey: .algorithm
        )
        try container.encodeIfPresent(self.overTls ? self.overTls : nil, forKey: .overTls)
    }
}

extension CryptoAlgorithm: Codable {}
