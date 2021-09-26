//
//  File.swift
//  
//
//  Created by Paul Harrison on 9/26/21.
//

import NIOSSL

public class SSLDecryptionConfiguration: Codable {
    public var skipServerCertificateVerification: Bool
    public var hostnames: [String] = [] {
        didSet {
            let pool = self.pool
            self.pool.removeAll()
            
            guard !hostnames.isEmpty else {
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
                }
            } catch {
                preconditionFailure("Failed to sign ssl server certificate for sites \(hostnames.joined(separator: ",")).")
            }
        }
    }
    public var base64EncodedP12String: String
    public var passphrase: String
    
    public var pool: [String : NIOSSLPKCS12Bundle] = [:]
    
    enum CodingKeys: String, CodingKey {
        case skipServerCertificateVerification
        case hostnames
        case base64EncodedP12String
        case passphrase
    }
    
    public init(skipServerCertificateVerification: Bool,
                hostnames: [String],
                base64EncodedP12String: String,
                passphrase: String) {
        self.skipServerCertificateVerification = skipServerCertificateVerification
        // Filter hostname if host contains in a wildcard host. e.g. apple.com and *.apple.com
        self.passphrase = "9BJB6U78"
        self.base64EncodedP12String = "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"
        
        ({ self.hostnames = hostnames })()
    }
}
