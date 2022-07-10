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
import NIOSSL

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

/// This class allow us to store `X509` CA certificate and it's private key.
///
/// This class also provides several convenience constructors that allow users to obtain an in-memory representation of a certificates from PKCS12 or base64 encoded PCKS12 string.
public class CertificateStore {

    /// X509 certificate.
    var certificate: OpaquePointer

    /// EVP_PKey
    var privateKey: UnsafeMutablePointer<EVP_PKEY>

    /// Initialize an instance of `CertificateStore` with specified X509 CA certificate and privateKey.
    /// - Parameters:
    ///   - certificate: The CA certificate.
    ///   - privateKey: The private key for CA.
    init(certificate: OpaquePointer, privateKey: UnsafeMutablePointer<EVP_PKEY>) {
        self.certificate = certificate
        self.privateKey = privateKey
    }

    /// Initialize an instance of `CertificateStore` with specified passphrase and base64 encoded PKCS12 string.
    ///
    /// This method will parse base64 encoded PKCS12 string to X509 CA certificate and private key.
    /// - Parameters:
    ///   - passphrase: The passphrase for PKCS12.
    ///   - base64EncodedP12String: Base64 encoded PKCS12 string.
    public convenience init(passphrase: String?, base64EncodedP12String: String) throws {
        CNIOBoringSSL_CRYPTO_library_init()

        guard let buffer = Data(base64Encoded: base64EncodedP12String) else {
            throw BoringSSLError.unknownError([])
        }

        let p12 = buffer.withUnsafeBytes { pointer -> OpaquePointer? in
            let bio = CNIOBoringSSL_BIO_new_mem_buf(pointer.baseAddress, CInt(pointer.count))!
            defer {
                CNIOBoringSSL_BIO_free(bio)
            }
            return CNIOBoringSSL_d2i_PKCS12_bio(bio, nil)
        }

        guard let p12 = p12 else {
            throw BoringSSLError.unknownError(BoringSSLError.buildErrorStack())
        }

        try self.init(passphrase: passphrase, p12: p12)
    }

    /// Initialize an instance of `CertificateStore` with specified passphrase and PKCS12.
    ///
    /// This method will parse PKCS12 to X509 CA certificate and private key.
    /// - Parameters:
    ///   - passphrase: The passphrase for PKCS12.
    ///   - p12: The PKCS12 bundle.
    convenience init(passphrase: String?, p12: OpaquePointer) throws {
        var pkey: UnsafeMutablePointer<EVP_PKEY>? = nil
        var cert: OpaquePointer? /*<X509>*/ = nil
        var caCerts: OpaquePointer? = nil

        let rc = CNIOBoringSSL_PKCS12_parse(p12, passphrase, &pkey, &cert, &caCerts)

        guard rc == 1 else {
            throw BoringSSLError.unknownError(BoringSSLError.buildErrorStack())
        }

        // Successfully parsed, let's unpack. The key and cert are mandatory,
        // the ca stack is not.
        guard let actualCert = cert, let actualKey = pkey else {
            fatalError("Failed to obtain cert and pkey from a PKC12 file")
        }

        self.init(certificate: actualCert, privateKey: actualKey)
    }

    /// Initialize an instance of `CertificateStore` with specified organization and commonName.
    ///
    /// This method will generate a new CA certificate and private key with organization and commonName.
    /// - Parameters:
    ///   - organization: The certificate organization.
    ///   - commonName: The certificate common name.
    public convenience init(organization: String, commonName: String) {
        let privateKey = CertificateStore.generateRSAPrivateKey()

        let name = CNIOBoringSSL_X509_NAME_new()
        defer {
            CNIOBoringSSL_X509_NAME_free(name)
        }
        CNIOBoringSSL_X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, organization, -1, -1, 0)
        CNIOBoringSSL_X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, commonName, -1, -1, 0)

        let certificate = CNIOBoringSSL_X509_new()!
        CNIOBoringSSL_X509_set_version(certificate, Int(X509_VERSION_3))

        // NB: X509_set_serialNumber uses an internal copy of the ASN1_INTEGER, so this is
        // safe, there will be no use-after-free.
        var serial = CertificateStore.randomSerialNumber()
        CNIOBoringSSL_X509_set_serialNumber(certificate, &serial)

        CNIOBoringSSL_X509_set_subject_name(certificate, name)

        // Give ourselves 10 years
        CNIOBoringSSL_X509_gmtime_adj(CNIOBoringSSL_X509_get_notBefore(certificate), 0)
        CNIOBoringSSL_X509_gmtime_adj(
            CNIOBoringSSL_X509_get_notAfter(certificate),
            86400 * 365 * 10
        )

        CNIOBoringSSL_X509_set_issuer_name(certificate, name)

        CNIOBoringSSL_X509_set_pubkey(certificate, privateKey)

        CertificateStore.boringSSLX509AddExtension(
            x509: certificate,
            nid: NID_basic_constraints,
            value: "critical, CA:TRUE"
        )
        CertificateStore.boringSSLX509AddExtension(
            x509: certificate,
            nid: NID_ext_key_usage,
            value: "serverAuth"
        )
        CertificateStore.boringSSLX509AddExtension(
            x509: certificate,
            nid: NID_key_usage,
            value: "critical, keyCertSign, cRLSign"
        )
        CertificateStore.boringSSLX509AddExtension(
            x509: certificate,
            nid: NID_subject_key_identifier,
            value: "hash"
        )

        CNIOBoringSSL_X509_sign(certificate, privateKey, CNIOBoringSSL_EVP_sha256())

        self.init(certificate: certificate, privateKey: privateKey)
    }

    deinit {
        CNIOBoringSSL_X509_free(certificate)
        CNIOBoringSSL_EVP_PKEY_free(privateKey)
    }

    /// This function generates a random number suitable for use in an X509
    /// serial field. This needs to be a positive number less than 2^159
    /// (such that it will fit into 20 ASN.1 bytes).
    /// This also needs to be portable across operating systems, and the easiest
    /// way to do that is to use either getentropy() or read from urandom. Sadly
    /// we need to support old Linuxes which may not possess getentropy as a syscall
    /// (and definitely don't support it in glibc), so we need to read from urandom.
    /// In the future we should just use getentropy and be happy.
    private static func randomSerialNumber() -> ASN1_INTEGER {
        let bytesToRead = 20
        let fd = open("/dev/urandom", O_RDONLY)
        precondition(fd != -1)
        defer {
            close(fd)
        }

        var readBytes = Array.init(repeating: UInt8(0), count: bytesToRead)
        let readCount = readBytes.withUnsafeMutableBytes {
            return read(fd, $0.baseAddress, bytesToRead)
        }
        precondition(readCount == bytesToRead)

        // Our 20-byte number needs to be converted into an integer. This is
        // too big for Swift's numbers, but BoringSSL can handle it fine.
        let bn = CNIOBoringSSL_BN_new()
        defer {
            CNIOBoringSSL_BN_free(bn)
        }

        _ = readBytes.withUnsafeBufferPointer {
            CNIOBoringSSL_BN_bin2bn($0.baseAddress, $0.count, bn)
        }

        // We want to bitshift this right by 1 bit to ensure it's smaller than
        // 2^159.
        CNIOBoringSSL_BN_rshift1(bn, bn)

        // Now we can turn this into our ASN1_INTEGER.
        var asn1int = ASN1_INTEGER()
        CNIOBoringSSL_BN_to_ASN1_INTEGER(bn, &asn1int)

        return asn1int
    }

    /// Generate RSA `EVP_PKEY` with specified bits.
    /// - Parameter size: Number of bits for `EVP_PKEY`.
    /// - Returns: The generated `EVP_PKEY`.
    static func generateRSAPrivateKey(size: CInt = 2048) -> UnsafeMutablePointer<EVP_PKEY> {
        let exponent = CNIOBoringSSL_BN_new()
        defer {
            CNIOBoringSSL_BN_free(exponent)
        }

        CNIOBoringSSL_BN_set_u64(exponent, 0x10001)

        let rsa = CNIOBoringSSL_RSA_new()!
        let generateRC = CNIOBoringSSL_RSA_generate_key_ex(rsa, size, exponent, nil)
        precondition(generateRC == 1)

        let pkey = CNIOBoringSSL_EVP_PKEY_new()!
        let assignRC = CNIOBoringSSL_EVP_PKEY_assign(pkey, EVP_PKEY_RSA, rsa)

        precondition(assignRC == 1)
        return pkey
    }

    /// Generate certificate with specifed common name organization subject alt names and pubkey.
    /// - Parameters:
    ///   - commonName: Common name for certificate.
    ///   - organization: Organization for certificate.
    ///   - subjectAltNames: Subject Alt Name for that certificate.
    ///   - pubkey: Pubkey for certificate.
    /// - Returns: Generated certificate if success.
    func generateCertificate(
        commonName: String,
        organization: String? = nil,
        subjectAltNames: [String],
        pubkey: UnsafeMutablePointer<EVP_PKEY>
    ) -> OpaquePointer {
        /* Sign with the CA. */
        let certificate = CNIOBoringSSL_X509_new()!
        /* Set version to X509v3 */
        CNIOBoringSSL_X509_set_version(certificate, Int(X509_VERSION_3))

        // NB: X509_set_serialNumber uses an internal copy of the ASN1_INTEGER, so this is
        // safe, there will be no use-after-free.
        var serial = CertificateStore.randomSerialNumber()
        CNIOBoringSSL_X509_set_serialNumber(certificate, &serial)

        /* Set issuer to CA's subject. */
        CNIOBoringSSL_X509_set_issuer_name(
            certificate,
            CNIOBoringSSL_X509_get_subject_name(self.certificate)
        )

        /* Set validity of certificate to 1 years. */
        CNIOBoringSSL_X509_gmtime_adj(CNIOBoringSSL_X509_get_notBefore(certificate), 0)
        CNIOBoringSSL_X509_gmtime_adj(CNIOBoringSSL_X509_get_notAfter(certificate), 86400 * 365)

        /* Set the DN of the request. */
        let name = CNIOBoringSSL_X509_NAME_new()
        defer {
            CNIOBoringSSL_X509_NAME_free(name)
        }

        if commonName.count < 64 {
            CNIOBoringSSL_X509_NAME_add_entry_by_txt(
                name,
                "CN",
                MBSTRING_ASC,
                commonName,
                -1,
                -1,
                0
            )
        }
        if let organization = organization {
            CNIOBoringSSL_X509_NAME_add_entry_by_txt(
                name,
                "O",
                MBSTRING_ASC,
                organization,
                -1,
                -1,
                0
            )
        }

        CNIOBoringSSL_X509_set_subject_name(certificate, name)

        CNIOBoringSSL_X509_set_pubkey(certificate, pubkey)

        let subjectAltName = subjectAltNames.map {
            "DNS:\($0)"
        }.joined(separator: ",")
        CertificateStore.boringSSLX509AddExtension(
            x509: certificate,
            nid: NID_subject_alt_name,
            value: subjectAltName
        )

        /* Now perform the actual signing with the CA. */
        CNIOBoringSSL_X509_sign(certificate, self.privateKey, CNIOBoringSSL_EVP_sha256())

        return certificate
    }

    /// Static method to export given certificate and private key to `NIOSSLPKCS12Bundle`.
    /// - Parameters:
    ///   - passphrase: The passphrase for NIOSSLPKCS12Bundle.
    ///   - name: Friendly name for PKCS12.
    ///   - certificate: X509 certificate.
    ///   - privateKey: Private key for certificate.
    /// - Returns: Generated NIOSSLPKCS12Bundle.
    static func exportP12Bundle(
        passphrase: String?,
        name: String? = nil,
        certificate: OpaquePointer,
        privateKey: UnsafeMutablePointer<EVP_PKEY>
    ) throws -> NIOSSLPKCS12Bundle {
        let certificateStore = CertificateStore(certificate: certificate, privateKey: privateKey)
        let buffer = try CertificateStore.convertP12ToDERBytes(
            certificateStore.exportP12Bundle(passphrase: passphrase, name: name)
        )
        return try NIOSSLPKCS12Bundle(buffer: buffer, passphrase: passphrase?.utf8)
    }

    /// Export self to base64 encoded p12 string.
    /// - Parameter passphrase: Passphrase for P12.
    /// - Returns: Base64 encoded p12 string if success.
    public func exportBase64EncodedP12String(passphrase: String? = nil) throws -> String {
        let p12 = try exportP12Bundle(passphrase: passphrase)
        return Data(try CertificateStore.convertP12ToDERBytes(p12)).base64EncodedString()
    }

    /// Export self to p12 bundle.
    /// - Parameters:
    ///   - passphrase: Passphrase for P12.
    ///   - name: Friendly name for P12.
    /// - Returns: PKCS12 if success.
    func exportP12Bundle(passphrase: String? = nil, name: String? = nil) throws -> OpaquePointer {
        var p12: OpaquePointer?
        if let passphrase = passphrase {
            p12 = passphrase.withCString {
                CNIOBoringSSL_PKCS12_create($0, name, privateKey, certificate, nil, 0, 0, 0, 0, 0)
            }
        } else {
            p12 = CNIOBoringSSL_PKCS12_create(
                nil,
                name,
                privateKey,
                certificate,
                nil,
                0,
                0,
                0,
                0,
                0
            )
        }

        guard let p12 = p12 else {
            throw BoringSSLError.unknownError(BoringSSLError.buildErrorStack())
        }

        return p12
    }

    /// Convert given PCKS12 to DER bytes.
    /// - Parameter p12: The PKCS12 to convert.
    /// - Returns: Converted DER bytes array.
    static func convertP12ToDERBytes(_ p12: OpaquePointer) throws -> [UInt8] {
        guard let bio = CNIOBoringSSL_BIO_new(CNIOBoringSSL_BIO_s_mem()) else {
            fatalError("Failed to malloc for a BIO handler")
        }
        defer {
            CNIOBoringSSL_BIO_free(bio)
        }

        let rc = CNIOBoringSSL_i2d_PKCS12_bio(bio, p12)
        guard rc == 1 else {
            throw BoringSSLError.unknownError(BoringSSLError.buildErrorStack())
        }

        var dataPtr: UnsafeMutablePointer<CChar>? = nil
        let length = CNIOBoringSSL_BIO_get_mem_data(bio, &dataPtr)

        guard let bytes = dataPtr.map({ UnsafeRawBufferPointer(start: $0, count: length) }) else {
            fatalError("Failed to map bytes from a certificate")
        }
        return Array(bytes)
    }

    private static func boringSSLX509AddExtension(x509: OpaquePointer, nid: CInt, value: String) {
        var ctx = X509V3_CTX()

        CNIOBoringSSL_X509V3_set_ctx(&ctx, x509, x509, nil, nil, 0)
        let ext = value.withCString { (pointer) in
            return CNIOBoringSSL_X509V3_EXT_nconf_nid(
                nil,
                &ctx,
                nid,
                UnsafeMutablePointer(mutating: pointer)
            )
        }!

        CNIOBoringSSL_X509_add_ext(x509, ext, -1)
        CNIOBoringSSL_X509_EXTENSION_free(ext)
    }
}
