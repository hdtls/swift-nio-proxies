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

#if compiler(>=5.1)
@_implementationOnly import CNIOBoringSSL
#else
import CNIOBoringSSL
#endif
import NIOSSL

/// Configuration for HTTPS traffic decraption with MitM attacks.
public struct MitMConfiguration: Codable {
    
    public var skipServerCertificateVerification: Bool
    
    /// Hostnames that should perform MitM.
    public var hostnames: [String] = [] {
        didSet {
            let pool = self.pool
            self.pool.removeAll()
            
            guard !hostnames.isEmpty, let passphrase = passphrase, let base64EncodedP12String = base64EncodedP12String else {
                return
            }
            
            do {
                let bundle = try boringSSLParseBase64EncodedPKCS12BundleString(
                    passphrase: passphrase,
                    base64EncodedString: base64EncodedP12String
                )
                
                try self.hostnames.forEach { hostname in
                    guard pool[hostname] == nil else {
                        self.pool[hostname] = pool[hostname]
                        return
                    }
                    
                    let p12 = try boringSSLSelfSignedPKCS12Bundle(
                        passphrase: passphrase,
                        certificate: bundle.certificateChain[0],
                        privateKey: bundle.privateKey, hostname: hostname
                    )
                    
                    self.pool[hostname] = try NIOSSLPKCS12Bundle(
                        buffer: boringSSLPKCS12BundleDERBytes(p12),
                        passphrase: Array(passphrase.utf8)
                    )
                    
                    CNIOBoringSSL_PKCS12_free(p12)
                }
            } catch {
                fatalError("Failed to sign ssl server certificate for sites \(hostnames.joined(separator: ",")).")
            }
        }
    }
    
    /// Base64 encoded CA P12 bundle.
    public var base64EncodedP12String: String?
    
    /// Passphrase for P12 bundle.
    public var passphrase: String?
    
    /// P12 bundle pool keyed by hostname.
    internal var pool: [String : NIOSSLPKCS12Bundle] = [:]
    
    enum CodingKeys: String, CodingKey {
        case skipServerCertificateVerification = "skip-server-cert-verification"
        case hostnames = "hostname"
        case passphrase = "ca-passphrase"
        case base64EncodedP12String = "ca-p12"
    }
    
    public init(skipServerCertificateVerification: Bool = false,
                hostnames: [String] = [],
                base64EncodedP12String: String? = nil,
                passphrase: String? = nil) {
        self.skipServerCertificateVerification = skipServerCertificateVerification
        // Filter hostname if host contains in a wildcard host. e.g. apple.com and *.apple.com
        self.passphrase = passphrase
        self.base64EncodedP12String = base64EncodedP12String
        // Workaround for `didSet` not call when setting new value in `init`.
        ({ self.hostnames = hostnames })()
    }
    
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        
        skipServerCertificateVerification = try container.decode(Bool.self, forKey: .skipServerCertificateVerification)
        let stringLiternal = try container.decode(String.self, forKey: .hostnames)
        hostnames = stringLiternal.split(separator: ",").map {
            $0.trimmingCharacters(in: .whitespaces)
        }
        base64EncodedP12String = try container.decode(String.self, forKey: .base64EncodedP12String)
        passphrase = try container.decode(String.self, forKey: .passphrase)
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        
        try container.encode(skipServerCertificateVerification, forKey: .skipServerCertificateVerification)
        try container.encode(hostnames.joined(separator: ", "), forKey: .hostnames)
        try container.encode(base64EncodedP12String, forKey: .base64EncodedP12String)
        try container.encode(passphrase, forKey: .passphrase)
    }
}
