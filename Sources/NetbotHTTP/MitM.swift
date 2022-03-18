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
        case skipServerCertificateVerification
        case hostnames
        case passphrase
        case base64EncodedP12String
    }
    
    /// Initialize an instance of `MitMConfiguration` with specified skipServerCertificateVerification, hostnames, base64EncodedP12String, passphrase.
    /// - Parameters:
    ///   - skipServerCertificateVerification: A boolean value determinse whether client should skip server certificate verification.
    ///   - hostnames: Hostnames use when decript.
    ///   - base64EncodedP12String: The base64 encoded p12 certificate bundle string.
    ///   - passphrase: Passphrase for p12 bundle.
    public init(skipServerCertificateVerification: Bool,
                hostnames: [String],
                base64EncodedP12String: String?,
                passphrase: String?) {
        self.skipServerCertificateVerification = skipServerCertificateVerification
        // Filter hostname if host contains in a wildcard host. e.g. apple.com and *.apple.com
        self.passphrase = passphrase
        self.base64EncodedP12String = base64EncodedP12String
        // Workaround for `didSet` not call when setting new value in `init`.
        ({ self.hostnames = hostnames })()
    }
    
    /// Initialize an instance of `MitMConfiguration`.
    ///
    /// Calling this method is equivalent to calling
    /// `init(skipServerCertificateVerification:hostnames:base64EncodedP12String:passphrase:)`
    /// with a default skipServerCertificateVerification, hostnames, base64EncodedP12String and passphrase values.
    public init() {
        self.init(skipServerCertificateVerification: false, hostnames: [], base64EncodedP12String: nil, passphrase: nil)
    }
}

extension MitMConfiguration: Equatable {
    
    public static func == (lhs: MitMConfiguration, rhs: MitMConfiguration) -> Bool {
        lhs.skipServerCertificateVerification == rhs.skipServerCertificateVerification
        && lhs.hostnames == rhs.hostnames
        && lhs.base64EncodedP12String == rhs.base64EncodedP12String
        && lhs.passphrase == rhs.passphrase
    }
}
