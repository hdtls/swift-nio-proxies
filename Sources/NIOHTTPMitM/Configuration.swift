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

@_implementationOnly import CNIOBoringSSL
import Foundation

/// Configuration for HTTPS traffic decraption with MitM attacks.
public struct Configuration: Codable, Equatable {

    /// A boolean value determinse whether ssl should skip server cerfitication verification.
    public var skipServerCertificateVerification: Bool

    /// Hostnames that should perform MitM.
    public var hostnames: [String]

    /// Base64 encoded CA P12 bundle.
    public var base64EncodedP12String: String?

    /// Passphrase for P12 bundle.
    public var passphrase: String?

    /// P12 bundle pool keyed by hostname.
    public var pool: [String: NIOSSLPKCS12Bundle] {
        return buildP12BundlePool()
    }

    /// Initialize an instance of `Configuration` with specified skipServerCertificateVerification, hostnames, base64EncodedP12String, passphrase.
    /// - Parameters:
    ///   - skipServerCertificateVerification: A boolean value determinse whether client should skip server certificate verification.
    ///   - hostnames: Hostnames use when decript.
    ///   - base64EncodedP12String: The base64 encoded p12 certificate bundle string.
    ///   - passphrase: Passphrase for p12 bundle.
    public init(
        skipServerCertificateVerification: Bool,
        hostnames: [String],
        base64EncodedP12String: String?,
        passphrase: String?
    ) {
        self.skipServerCertificateVerification = skipServerCertificateVerification
        self.hostnames = hostnames
        self.passphrase = passphrase
        self.base64EncodedP12String = base64EncodedP12String
    }

    /// Initialize an instance of `Configuration`.
    ///
    /// Calling this method is equivalent to calling
    /// `init(skipServerCertificateVerification:hostnames:base64EncodedP12String:passphrase:)`
    /// with a default skipServerCertificateVerification, hostnames, base64EncodedP12String and passphrase values.
    public init() {
        self.init(
            skipServerCertificateVerification: false,
            hostnames: [],
            base64EncodedP12String: nil,
            passphrase: nil
        )
    }

    private func buildP12BundlePool() -> [String: NIOSSLPKCS12Bundle] {
        guard !hostnames.isEmpty, let passphrase = passphrase,
            let base64EncodedP12String = base64EncodedP12String
        else {
            return [:]
        }

        guard
            let certificateStore = try? CertificateStore.init(
                passphrase: passphrase,
                base64EncodedP12String: base64EncodedP12String
            )
        else {
            return [:]
        }

        var pool: [String: NIOSSLPKCS12Bundle] = [:]

        try? hostnames.forEach { hostname in
            let privateKey = CertificateStore.generateRSAPrivateKey()
            let certificate = certificateStore.generateCertificate(
                commonName: hostname,
                subjectAltNames: [hostname],
                pubkey: privateKey
            )
            pool[hostname] = try CertificateStore.exportP12Bundle(
                passphrase: passphrase,
                certificate: certificate,
                privateKey: privateKey
            )
        }

        return pool
    }
}

//extension Configuration: Equatable {
//
//    public static func == (lhs: Configuration, rhs: Configuration) -> Bool {
//        lhs.skipServerCertificateVerification == rhs.skipServerCertificateVerification
//            && lhs.hostnames == rhs.hostnames
//            && lhs.base64EncodedP12String == rhs.base64EncodedP12String
//            && lhs.passphrase == rhs.passphrase
//    }
//}
