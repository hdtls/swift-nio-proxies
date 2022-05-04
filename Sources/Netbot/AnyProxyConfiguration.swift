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

struct AnyProxyConfiguration {

    var serverAddress: String

    var port: Int

    var username: String?

    var password: String?

    var prefererHttpTunneling: Bool

    var skipCertificateVerification: Bool

    var sni: String?

    var certificatePinning: String?

    var algo: CryptoAlgorithm?

    init(
        serverAddress: String = "",
        port: Int = 8080,
        username: String? = "",
        password: String? = "",
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
}

extension AnyProxyConfiguration: Codable {

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

    init(from decoder: Decoder) throws {
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

    func encode(to encoder: Encoder) throws {
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

extension AnyProxyConfiguration: SocketConfigurationProtocol {}

extension AnyProxyConfiguration: HTTPProxyConfigurationProtocol {}

extension AnyProxyConfiguration: TLSConfigurationProtocol {}

extension AnyProxyConfiguration: ShadowsocksConfigurationProtocol {

    var algorithm: CryptoAlgorithm {
        algo ?? .aes128Gcm
    }

    var passwordReference: String {
        assert(password != nil, "Shadowsocks MUST provide password to secure connection.")
        return password ?? ""
    }
}

extension AnyProxyConfiguration: SOCKS5ConfigurationProtocol {}

extension AnyProxyConfiguration: VMESSConfigurationProtocol {

    var user: UUID {
        guard let uuidString = username, let uuid = UUID(uuidString: uuidString) else {
            assertionFailure("VMESS MUST provide valid UUID string as username.")
            return UUID()
        }
        return uuid
    }
}
