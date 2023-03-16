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

import NIONetbot

extension Proxy: Codable {

    private enum CodingKeys: CodingKey {
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

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let serverAddress = try container.decode(String.self, forKey: .serverAddress)
        let port = try container.decode(Int.self, forKey: .port)
        let `protocol` = try container.decode(`Protocol`.self, forKey: .protocol)
        let username = try container.decodeIfPresent(String.self, forKey: .username) ?? ""
        let password = try container.decodeIfPresent(String.self, forKey: .password) ?? ""
        let authenticationRequired =
            try container.decodeIfPresent(Bool.self, forKey: .authenticationRequired) ?? false
        let prefererHttpTunneling =
            try container.decodeIfPresent(Bool.self, forKey: .prefererHttpTunneling) ?? false
        let skipCertificateVerification =
            try container.decodeIfPresent(Bool.self, forKey: .skipCertificateVerification) ?? false
        let sni = try container.decodeIfPresent(String.self, forKey: .sni) ?? ""
        let certificatePinning =
            try container.decodeIfPresent(String.self, forKey: .certificatePinning) ?? ""
        let algorithm: Algorithm
        if let algorithmRawValue =
            try container.decodeIfPresent(String.self, forKey: .algorithm)
        {
            algorithm = .init(rawValue: algorithmRawValue) ?? .aes128Gcm
        } else {
            algorithm = .aes128Gcm
        }
        let overTls = try container.decodeIfPresent(Bool.self, forKey: .overTls) ?? false

        self.init(
            serverAddress: serverAddress, port: port, protocol: `protocol`, username: username,
            password: password, authenticationRequired: authenticationRequired,
            prefererHttpTunneling: prefererHttpTunneling, overTls: overTls,
            skipCertificateVerification: skipCertificateVerification, sni: sni,
            certificatePinning: certificatePinning, algorithm: algorithm)
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
            self.algorithm != .aes128Gcm ? self.algorithm.rawValue : nil,
            forKey: .algorithm
        )
        try container.encodeIfPresent(self.overTls ? self.overTls : nil, forKey: .overTls)
    }
}
