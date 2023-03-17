//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2022 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOSSL

/// Certificate store used to generate server certificate when perform HTTP MitM Attack.
public actor CertificateStore {

    var pool: [String: NIOSSLPKCS12Bundle] = [:]
    var hostnames: [String] = []
    private var ca: CertificateAuthority
    private var passphrase: String?

    /// Initialize an instance of `CertificateStore` with specified passphrase and base64 encoded p12 string.
    /// - Parameters:
    ///   - passphrase: The passphrase for this p12 bundle.
    ///   - base64EncodedP12String: The base64 encoded p12 bundle string.
    public init(passphrase: String?, base64EncodedP12String: String) throws {
        self.ca = try .init(passphrase: passphrase, base64EncodedP12String: base64EncodedP12String)
        self.passphrase = passphrase
        self.pool = [:]
    }

    /// Update MitM hostnames.
    /// - Parameter newValue: The hosts witch allow MitM decryption.
    public func setUpMitMHosts(_ newValue: [String]) {
        newValue.difference(from: hostnames).removals.forEach {
            switch $0 {
                case .insert(offset: _, element: _, associatedWith: _):
                    break
                case .remove(offset: _, element: let host, associatedWith: _):
                    pool.removeValue(forKey: host)
            }
        }
        hostnames = newValue
    }

    /// Check whether host should perform MitM if possible.
    /// - Parameter host: The hostname to check.
    /// - Returns: Ture if should perform MitM or false.
    public func shouldPerformMitMIfPossible(for host: String) -> Bool {
        poolKey(for: host) != nil
    }

    private func poolKey(for host: String) -> String? {
        hostnames.filter {
            guard $0.hasPrefix("*.") else {
                return $0 == host
            }
            return host.hasSuffix($0.suffix($0.count - 1))
        }.first
    }

    /// Find `NIOSSLPKCS12Bundle` with hostname in mitm store.
    /// - Parameter serverHostname: The key identified p12 store in certs pool.
    /// - Returns: The `NIOSSLPKCS12Bundle` if find or nil.
    public func certificate(identifiedBy serverHostname: String) throws -> NIOSSLPKCS12Bundle? {
        guard let key = poolKey(for: serverHostname) else {
            return nil
        }

        guard let bundle = pool[key] else {
            let privateKey = CertificateAuthority.generateRSAPrivateKey()
            let certificate = ca.generateCertificate(
                commonName: key,
                subjectAltNames: [key],
                pubkey: privateKey
            )
            let bundle = try CertificateAuthority.exportP12Bundle(
                passphrase: passphrase,
                certificate: certificate,
                privateKey: privateKey
            )
            pool[key] = bundle
            return bundle
        }

        return bundle
    }
}
