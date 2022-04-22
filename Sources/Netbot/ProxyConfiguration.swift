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

import EraseNilDecoding
import Foundation

public struct DefaultAlgo: EraseNilDecodable {
    public static let erasedValue: CryptoAlgorithm = .aes128Gcm
}

public struct ProxyConfiguration: Codable {

    public var serverAddress: String

    public var port: Int

    public var username: String?

    public var password: String?

    @EraseNilToFalse public var prefererHttpTunneling: Bool

    @EraseNilToFalse public var skipCertificateVerification: Bool

    @EraseNilToEmpty public var sni: String

    @EraseNilToEmpty public var certificatePinning: String

    @EraseNilDecoding<DefaultAlgo> public var algorithm: CryptoAlgorithm

    init(
        serverAddress: String = "",
        port: Int = 8080,
        username: String = "",
        password: String = "",
        prefererHttpTunneling: Bool = false,
        skipCertificateVerification: Bool = false,
        sni: String = "",
        certificatePinning: String = "",
        algorithm: CryptoAlgorithm = .aes128Gcm
    ) {
        self.serverAddress = serverAddress
        self.port = port
        self.username = username
        self.password = password
        self.prefererHttpTunneling = prefererHttpTunneling
        self.skipCertificateVerification = skipCertificateVerification
        self.sni = sni
        self.certificatePinning = certificatePinning
        self.algorithm = algorithm
    }
}

extension ProxyConfiguration: SocketConfigurationProtocol {}

extension ProxyConfiguration: HTTPProxyConfigurationProtocol {}

extension ProxyConfiguration: TLSConfigurationConvertible {

    public func asTLSClientConfiguration() -> TLSConfiguration {
        let tlsConfiguration = TLSConfiguration.makeClientConfiguration()
        return tlsConfiguration
    }
}

extension ProxyConfiguration: ShadowsocksConfigurationProtocol {

    public var passwordReference: String {
        assert(password != nil, "Shadowsocks MUST provide password to secure connection.")
        return password ?? ""
    }
}

extension ProxyConfiguration: SOCKS5ConfigurationProtocol {}

extension ProxyConfiguration: VMESSConfigurationProtocol {

    public var user: UUID {
        guard let uuidString = username, let uuid = UUID(uuidString: uuidString) else {
            assertionFailure("VMESS MUST provide valid UUID string as username.")
            return UUID()
        }
        return uuid
    }
}
