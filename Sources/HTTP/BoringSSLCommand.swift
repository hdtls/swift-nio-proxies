//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2017-2018 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import ArgumentParser
#if compiler(>=5.1)
@_implementationOnly import CNIOBoringSSL
#else
import CNIOBoringSSL
#endif
import Foundation
#if canImport(Security)
import Security
#endif

/// Wraps a single error from BoringSSL.
struct BoringSSLInternalError: Equatable, CustomStringConvertible {
    let errorCode: UInt32
    
    var errorMessage: String? {
        // TODO(cory): This should become non-optional in the future, as it always succeeds.
        var scratchBuffer = [CChar](repeating: 0, count: 512)
        return scratchBuffer.withUnsafeMutableBufferPointer { pointer in
            CNIOBoringSSL_ERR_error_string_n(self.errorCode, pointer.baseAddress!, pointer.count)
            return String(cString: pointer.baseAddress!)
        }
    }
    
    public var description: String {
        return "Error: \(errorCode) \(errorMessage ?? "")"
    }
    
    init(errorCode: UInt32) {
        self.errorCode = errorCode
    }
}

/// An enum that wraps individual BoringSSL errors directly.
enum BoringSSLError: Error {
    case unknownError([BoringSSLInternalError])
    
    static func buildErrorStack() -> [BoringSSLInternalError] {
        var errorStack = [BoringSSLInternalError]()
        
        while true {
            let errorCode = CNIOBoringSSL_ERR_get_error()
            if errorCode == 0 { break }
            errorStack.append(BoringSSLInternalError(errorCode: errorCode))
        }
        
        return errorStack
    }
}

struct SecurityInternalError: Equatable, CustomStringConvertible {
    let errorCode: OSStatus
    
    var errorMessage: String? {
        SecCopyErrorMessageString(errorCode, nil) as String?
    }
    
    public var description: String {
        return "Error: \(errorCode) \(String(describing: errorMessage))"
    }
    
    init(errorCode: OSStatus) {
        self.errorCode = errorCode
    }
}

enum SecurityError: Error {
    case failedToLoadCertificate
    case unknowError(SecurityInternalError)
}

public struct BoringSSLCommand: ParsableCommand {
    public static var configuration: CommandConfiguration = .init(commandName: "boringssl", abstract: "The BoringSSL Command Line Tool", subcommands: [RSAKeyCommand.self, NewCommand.self, InstallCommand.self])
    
    public init() {}
}

extension BoringSSLCommand {
    
    static func printPKCS12Bundle(_ base64EncodedString: String, passphrase: String) {
        let prettyPrint = """
-----BEGIN PKCS#12 BUNDLE-----

PART.1 passphrase:
\(passphrase)

PART.2 base64 encoded PKCS#12 bundle string:
\(base64EncodedString)

NOTE. write PART.1 and PART.2 to your config file to enable decrypt HTTPS traffic with MitM attack.

-----END PKCS#12 BUNDLE-----
"""
        print(prettyPrint)
    }
    
    public enum FileSerializationFormats: String, CaseIterable, ExpressibleByArgument {
        case der
        case pem
        case p12
        
        public init?(argument: String) {
            switch argument {
                case "der", "DER":
                    self = .der
                case "pem", "PEM":
                    self = .pem
                case "p12", "P12", "pkcs#12", "PKCS#12", "pkcs12", "PKCS12":
                    self = .p12
                default:
                    return nil
            }
        }
    }
    
    public struct RSAKeyCommand: ParsableCommand {
        public static var configuration: CommandConfiguration = .init(commandName: "genrsa", abstract: "Generates rsa key with numbits.")
        
        @Argument(help: "The size of the private key to generate in bits.")
        public var numbits: Int = 2048
        
        @Option(help: "The output file to write to, or standard output if not specified.")
        public var out: String?
        
        @Option(help: "The output file format, only valid when `out` is specified.")
        public var outputFormat: FileSerializationFormats = .der
        
        public init() {}
        
        public func run() throws {
            let ref = boringSSLGenerateRSAPrivateKey()
            defer {
                CNIOBoringSSL_EVP_PKEY_free(ref)
            }
            
            guard let fileURLPath = out else {
                return
            }
            
            let file = try Posix.fopen(file: fileURLPath, mode: "w")
            defer {
                fclose(file)
            }
     
            switch outputFormat {
                case .der:
                    CNIOBoringSSL_i2d_PrivateKey_fp(file, ref)
                case .pem:
                    CNIOBoringSSL_PEM_write_PrivateKey(file, ref, nil, nil, 0, nil, nil)
                case .p12:
                    fatalError("RSA key only support DER or PEM file format.")
            }
        }
    }
    
    public struct NewCommand: ParsableCommand {
        
        public static var configuration: CommandConfiguration = .init(commandName: "new", abstract: "Generate new CA PKCS#12 bundle with passphrase.")
        
        @Option(help: "The passphrase for PKCS#12 bundle, or generated automatically if not specified.")
        public var passphrase: String?
        
        public init() {}
        
        public func run() throws {
            let passphrase = passphrase ?? String((0...7).map { _ in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".randomElement()! })
            let commonName = "Netbot Root CA \(passphrase)"
            
            let (x509, privateKey) = boringSSLIssueCACertificate(commonName: commonName)
            
            let p12 = try boringSSLCreatePKCS12Bundle(passphrase: passphrase, name: commonName, certificate: x509, privateKey: privateKey)
            defer {
                CNIOBoringSSL_PKCS12_free(p12)
            }
            
            let bytes = try boringSSLPKCS12BundleDERBytes(p12)
            
            BoringSSLCommand.printPKCS12Bundle(Data(bytes).base64EncodedString(), passphrase: passphrase)
        }
    }
    
    public struct InstallCommand: ParsableCommand {
        public static var configuration: CommandConfiguration = .init(commandName: "install", abstract: "Install and trust the certificate and output base64 encoded PKCS#12 bundle msg.", discussion: "If `ca` option is specified we install this ca and it's key otherwise generate and install a new PKCS#12 bundle instead. No matter what type of CA certificate file you input, it will eventually output base64 encoded PKCS#12 bundle description.")
        
        @Option(help: "The input CA certificate file, or generate new one if not specified.")
        public var ca: String?
        
        @Option(help: "The input CA certificate format, only valid when `ca` is specified.")
        public var caFormat: FileSerializationFormats = .der

        @Option(help: "The input CA key file, only valid when `ca` is specified.")
        public var key: String?
        
        @Option(help: "The input CA certificate private key format, only valid when `ca` is specified.")
        public var keyFormat: FileSerializationFormats = .der
                
        @Option(help: "The passphrase for PKCS#12 file.")
        public var passphrase: String?
        
        public init() {}
        
        public func run() throws {
            var x509: OpaquePointer?
            let passphrase = passphrase ?? String((0...7).map { _ in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".randomElement()! })
            var base64EncodedPKCS12String: String
            let commonName = "Netbot Root CA \(passphrase)"

            if let fileURLPath = ca {
                precondition(caFormat == .p12 || key != nil, "CA key is required for create PKCS#12 bundle.")
                
                let file = try Posix.fopen(file: fileURLPath, mode: "rb")
                defer {
                    fclose(file)
                }
                
                switch caFormat {
                    case .der:
                        x509 = CNIOBoringSSL_d2i_X509_fp(file, nil)
                        guard x509 != nil else {
                            throw BoringSSLError.unknownError(BoringSSLError.buildErrorStack())
                        }
                        
                        let file = try Posix.fopen(file: key!, mode: "rb")
                        defer {
                            fclose(file)
                        }
                        
                        let p12 = try boringSSLCreatePKCS12Bundle(passphrase: passphrase, name: commonName, certificate: x509!, privateKey: CNIOBoringSSL_d2i_PrivateKey_fp(file, nil))
                        
                        base64EncodedPKCS12String = try boringSSLBase64EncodedPKCS12String(p12)
                    case .pem:
                        x509 = CNIOBoringSSL_PEM_read_X509(file, nil, nil, nil)
                        guard x509 != nil else {
                            throw BoringSSLError.unknownError(BoringSSLError.buildErrorStack())
                        }
                        
                        let file = try Posix.fopen(file: key!, mode: "rb")
                        defer {
                            fclose(file)
                        }
                        
                        let p12 = try boringSSLCreatePKCS12Bundle(passphrase: passphrase, name: commonName, certificate: x509!, privateKey: CNIOBoringSSL_PEM_read_PrivateKey(file, nil, nil, nil))
                        
                        base64EncodedPKCS12String = try boringSSLBase64EncodedPKCS12String(p12)
                    case .p12:
                        precondition(self.passphrase != nil, "Passphrase is required for parse PKCS#12 bundle.")
                        guard let p12 = CNIOBoringSSL_d2i_PKCS12_fp(file, nil) else {
                            throw BoringSSLError.unknownError(BoringSSLError.buildErrorStack())
                        }
                        
                        base64EncodedPKCS12String = try boringSSLBase64EncodedPKCS12String(p12)
                        let bundle = try boringSSLParseBase64EncodedPKCS12BundleString(passphrase: self.passphrase!, base64EncodedString: base64EncodedPKCS12String)
                        x509 = bundle.certificateChain.first
                }
            } else {
                let (certificate, privateKey) = boringSSLIssueCACertificate(commonName: commonName)
                
                let p12 = try boringSSLCreatePKCS12Bundle(passphrase: passphrase, name: commonName, certificate: certificate, privateKey: privateKey)
                defer {
                    CNIOBoringSSL_PKCS12_free(p12)
                }
                x509 = certificate
                base64EncodedPKCS12String = try boringSSLBase64EncodedPKCS12String(p12)
            }
            
            BoringSSLCommand.printPKCS12Bundle(base64EncodedPKCS12String, passphrase: passphrase)
            
#if canImport(Security)
            guard let bio = CNIOBoringSSL_BIO_new(CNIOBoringSSL_BIO_s_mem()) else {
                fatalError("Failed to malloc for a BIO handler")
            }
            defer {
                CNIOBoringSSL_BIO_free(bio)
            }
            
            // Map x509 to DER ecoded bytes.
            let rc = CNIOBoringSSL_i2d_X509_bio(bio, x509)
            guard rc == 1 else {
                throw BoringSSLError.unknownError(BoringSSLError.buildErrorStack())
            }
            
            var dataPtr: UnsafeMutablePointer<CChar>? = nil
            let length = CNIOBoringSSL_BIO_get_mem_data(bio, &dataPtr)
            
            guard let buffer = dataPtr.map({ UnsafeRawBufferPointer(start: $0, count: length) }) else {
                fatalError("Failed to map bytes from a certificate")
            }
            
            guard let certificate = SecCertificateCreateWithData(nil, Data(buffer) as CFData) else {
                throw SecurityError.failedToLoadCertificate
            }

            var status: OSStatus
            let attributes: [CFString: Any] = [
                kSecClass : kSecClassCertificate,
                kSecValueRef : certificate,
            ]
            
            status = SecItemAdd(attributes as CFDictionary, nil)
            guard status == errSecSuccess else {
                throw SecurityError.unknowError(SecurityInternalError(errorCode: status))
            }
            
            status = SecTrustSettingsSetTrustSettings(certificate, .user, [kSecTrustSettingsResult : NSNumber(value: SecTrustSettingsResult.trustRoot.rawValue)] as CFTypeRef)
            
            guard status == errSecSuccess else {
                throw SecurityError.unknowError(SecurityInternalError(errorCode: status))
            }
#endif
        }
    }
}
