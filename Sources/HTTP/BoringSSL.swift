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

#if compiler(>=5.1)
@_implementationOnly import CNIOBoringSSL
#else
import CNIOBoringSSL
#endif
import Foundation

/// This function generates a random number suitable for use in an X509
/// serial field. This needs to be a positive number less than 2^159
/// (such that it will fit into 20 ASN.1 bytes).
/// This also needs to be portable across operating systems, and the easiest
/// way to do that is to use either getentropy() or read from urandom. Sadly
/// we need to support old Linuxes which may not possess getentropy as a syscall
/// (and definitely don't support it in glibc), so we need to read from urandom.
/// In the future we should just use getentropy and be happy.
private func boringSSLGenerateSerialNumber() -> ASN1_INTEGER {
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

/// BoringSSL generate RSA private key.
/// - Returns: The RSA `EVP_PKEY`.
func boringSSLGenerateRSAPrivateKey() -> UnsafeMutablePointer<EVP_PKEY> {
    let exponent = CNIOBoringSSL_BN_new()
    defer {
        CNIOBoringSSL_BN_free(exponent)
    }
    
    CNIOBoringSSL_BN_set_u64(exponent, 0x10001)
    
    let rsa = CNIOBoringSSL_RSA_new()!
    let generateRC = CNIOBoringSSL_RSA_generate_key_ex(rsa, CInt(2048), exponent, nil)
    precondition(generateRC == 1)
    
    let pkey = CNIOBoringSSL_EVP_PKEY_new()!
    let assignRC = CNIOBoringSSL_EVP_PKEY_assign(pkey, EVP_PKEY_RSA, rsa)
    
    precondition(assignRC == 1)
    return pkey
}

private func boringSSLX509AddExtension(x509: OpaquePointer, nid: CInt, value: String) {
    var extensionContext = X509V3_CTX()
    
    CNIOBoringSSL_X509V3_set_ctx(&extensionContext, x509, x509, nil, nil, 0)
    let ext = value.withCString { (pointer) in
        return CNIOBoringSSL_X509V3_EXT_nconf_nid(nil, &extensionContext, nid, UnsafeMutablePointer(mutating: pointer))
    }!
    CNIOBoringSSL_X509_add_ext(x509, ext, -1)
    CNIOBoringSSL_X509_EXTENSION_free(ext)
}

private func boringSSLX509NameAddEntry(name: OpaquePointer?, nid: CInt, value: String) {
    value.withCString { pointer in
        pointer.withMemoryRebound(to: UInt8.self, capacity: value.lengthOfBytes(using: .utf8)) { pointer -> Void in
            CNIOBoringSSL_X509_NAME_add_entry_by_NID(name, nid, MBSTRING_UTF8, pointer, CInt(value.lengthOfBytes(using: .utf8)), -1, 0)
        }
    }
}

/// BoringSSL issue certificate authority certificate and it's private key.
/// - Returns: The CA certificate `X509` and `EVP_PKEY` pairs.
func boringSSLIssueCACertificate(privateKey: UnsafeMutablePointer<EVP_PKEY>? = nil, commonName: String) -> (OpaquePointer, UnsafeMutablePointer<EVP_PKEY>) {
    let pkey = privateKey ?? boringSSLGenerateRSAPrivateKey()
    let x = CNIOBoringSSL_X509_new()!
    CNIOBoringSSL_X509_set_version(x, 2)
    
    // NB: X509_set_serialNumber uses an internal copy of the ASN1_INTEGER, so this is
    // safe, there will be no use-after-free.
    var serial = boringSSLGenerateSerialNumber()
    CNIOBoringSSL_X509_set_serialNumber(x, &serial)
    
    let notBefore = CNIOBoringSSL_ASN1_TIME_new()!
    var now = time(nil)
    CNIOBoringSSL_ASN1_TIME_set(notBefore, now)
    CNIOBoringSSL_X509_set_notBefore(x, notBefore)
    CNIOBoringSSL_ASN1_TIME_free(notBefore)
    
    now += 86400 * 365 * 10 // Give ourselves 10 years
    let notAfter = CNIOBoringSSL_ASN1_TIME_new()!
    CNIOBoringSSL_ASN1_TIME_set(notAfter, now)
    CNIOBoringSSL_X509_set_notAfter(x, notAfter)
    CNIOBoringSSL_ASN1_TIME_free(notAfter)
    
    CNIOBoringSSL_X509_set_pubkey(x, pkey)
    
    let name = CNIOBoringSSL_X509_get_subject_name(x)
    
    boringSSLX509NameAddEntry(name: name, nid: NID_organizationName, value: "Netbot")
    boringSSLX509NameAddEntry(name: name, nid: NID_commonName, value: commonName)
    
    CNIOBoringSSL_X509_set_issuer_name(x, name)
    
    boringSSLX509AddExtension(x509: x, nid: NID_authority_key_identifier, value: "keyid,issuer")
    boringSSLX509AddExtension(x509: x, nid: NID_basic_constraints, value: "critical,CA:TRUE")
    boringSSLX509AddExtension(x509: x, nid: NID_subject_key_identifier, value: "hash")
    
    CNIOBoringSSL_X509_sign(x, pkey, CNIOBoringSSL_EVP_sha256())
    
    return (x, pkey)
}

/// BoringSSL create PKCS#12 bundle with passphrase friendly name certificate and privateKey.
/// - Parameters:
///   - passphrase: The passphrase for this PKCS#12 bundle.
///   - name: The friendly name for this PKCS#12 bundle.
///   - certificate: The certificate.
///   - privateKey: The privateKey for certificate.
/// - Throws: May throws BoringSSLError.unknownError.
/// - Returns: The PKCS#12 bundle.
func boringSSLCreatePKCS12Bundle(passphrase: String, name: String, certificate: OpaquePointer, privateKey: UnsafeMutablePointer<EVP_PKEY>) throws -> OpaquePointer {
    let p12 = try Array(passphrase.utf8).withSecureCString { passphrase in
        CNIOBoringSSL_PKCS12_create(passphrase, name, privateKey, certificate, nil, 0, 0, 0, 0, 0)
    }
    
    guard let p12 = p12 else {
        throw BoringSSLError.unknownError(BoringSSLError.buildErrorStack())
    }
    return p12
}

/// BoringSSL issue self signed certificate PKCS#12 bundle with passphrase, certificate authority and hostname.
/// - Parameters:
///   - passphrase: The passphrase for this PKCS#12 bundle.
///   - certificate: The certificate authority certificate.
///   - privateKey: The certificate authority certificate's privateKey.
///   - hostname: The hostname for this certificate.
/// - Throws: May throws BoringSSLError.unknownError.
/// - Returns: Self signed PKCS#12 bundle pointer.
func boringSSLSelfSignedPKCS12Bundle(passphrase: String, certificate: OpaquePointer, privateKey: UnsafeMutablePointer<EVP_PKEY>, hostname: String) throws -> OpaquePointer /*PKCS#12*/ {
    //    let passphrase = String((0...6).map { _ in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".randomElement()! })
    let pubkey = boringSSLGenerateRSAPrivateKey()
    let req = CNIOBoringSSL_X509_REQ_new()
    
    /* Set the public key. */
    CNIOBoringSSL_X509_REQ_set_pubkey(req, pubkey)
    
    /* Set the DN of the request. */
    let name = CNIOBoringSSL_X509_NAME_new()
    
    boringSSLX509NameAddEntry(name: name, nid: NID_organizationName, value: "Netbot")
    
    let splits = hostname.split(separator: ".")
    let commonName = splits.count > 2 ? splits.suffix(2).joined(separator: ".") : splits.joined(separator: ".")
    boringSSLX509NameAddEntry(name: name, nid: NID_commonName, value: commonName)
    
    CNIOBoringSSL_X509_REQ_set_subject_name(req, name)
    
    /* Self-sign the request to prove that we posses the key. */
    CNIOBoringSSL_X509_REQ_sign(req, pubkey, CNIOBoringSSL_EVP_sha256())
    
    /* Sign with the CA. */
    let x = CNIOBoringSSL_X509_new()!
    CNIOBoringSSL_X509_set_version(x, 2)
    
    // NB: X509_set_serialNumber uses an internal copy of the ASN1_INTEGER, so this is
    // safe, there will be no use-after-free.
    var serial = boringSSLGenerateSerialNumber()
    CNIOBoringSSL_X509_set_serialNumber(x, &serial)
    
    let notBefore = CNIOBoringSSL_ASN1_TIME_new()!
    var now = time(nil)
    CNIOBoringSSL_ASN1_TIME_set(notBefore, now)
    CNIOBoringSSL_X509_set_notBefore(x, notBefore)
    CNIOBoringSSL_ASN1_TIME_free(notBefore)
    
    now += 86400 * 365  // Give ourselves 1 year.
    let notAfter = CNIOBoringSSL_ASN1_TIME_new()!
    CNIOBoringSSL_ASN1_TIME_set(notAfter, now)
    CNIOBoringSSL_X509_set_notAfter(x, notAfter)
    CNIOBoringSSL_ASN1_TIME_free(notAfter)
    
    CNIOBoringSSL_X509_set_subject_name(x, name)
    CNIOBoringSSL_X509_set_pubkey(x, pubkey)
    
    /* Set issuer name to CA's subject. */
    CNIOBoringSSL_X509_set_issuer_name(x, CNIOBoringSSL_X509_get_subject_name(certificate))
    
    boringSSLX509AddExtension(x509: x, nid: NID_authority_key_identifier, value: "keyid,issuer")
    boringSSLX509AddExtension(x509: x, nid: NID_basic_constraints, value: "CA:FALSE")
    boringSSLX509AddExtension(x509: x, nid: NID_ext_key_usage, value: "serverAuth,OCSPSigning")
    boringSSLX509AddExtension(x509: x, nid: NID_key_usage, value: "critical,digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment")
    // Support top-level domain and all sub-domains with a wildcard character *.
    boringSSLX509AddExtension(x509: x, nid: NID_subject_alt_name, value: "DNS:\(commonName),DNS:*.\(commonName)")
    boringSSLX509AddExtension(x509: x, nid: NID_subject_key_identifier, value: "hash")
    
    CNIOBoringSSL_X509_sign(x, privateKey, CNIOBoringSSL_EVP_sha256())
    CNIOBoringSSL_X509_REQ_free(req)
    
    return try boringSSLCreatePKCS12Bundle(passphrase: passphrase, name: commonName, certificate: x, privateKey: pubkey)
}

/// BoringSSL PKCS#12 bundle from base64 encoded string and passphrase.
/// - Parameters:
///   - passphrase: The passphrase for this bundle.
///   - base64EncodedString: The base53 encoded PKCS#12 bundle bundle string.
/// - Throws: error
/// - Returns:  PKCS#12 bundle pointer.
func boringSSLPKCS12Bundle(base64EncodedString: String) throws -> OpaquePointer {
    CNIOBoringSSL_CRYPTO_library_init()
    
    guard let buffer = Data(base64Encoded: base64EncodedString) else {
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
    
    return p12
}

/// Convert  PKCS#12 bundle to DER bytes.
/// - Parameter p12: The  PKCS#12 bundle.
/// - Throws: error.
/// - Returns: The DER bytes for this  PKCS#12 bundle.
func boringSSLPKCS12BundleDERBytes(_ p12: OpaquePointer) throws -> [UInt8] {
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

/// Encode  PKCS#12 bundle to base64 encoded string.
/// - Parameter p12: The  PKCS#12 bundle.
/// - Throws: May throw BoringSSLError.unknownError.
/// - Returns: The base64 encoded string.
func boringSSLBase64EncodedPKCS12String(_ p12: OpaquePointer) throws -> String {
    return Data(try boringSSLPKCS12BundleDERBytes(p12)).base64EncodedString()
}

/// BoringSSL parse base64 encoded PKCS#12 bundle to certificate chain and private key with passphrase.
/// - Parameters:
///   - passphrase: The passphrase for this PKCS#12 bundle.
///   - base64EncodedString: The base64 encoded PKCS#12 bundle string.
/// - Throws: May throws unknowError.
/// - Returns: The certificate chain and private key.
func boringSSLParseBase64EncodedPKCS12BundleString(passphrase: String, base64EncodedString: String) throws -> (certificateChain: [OpaquePointer], privateKey: UnsafeMutablePointer<EVP_PKEY>) {
    let p12 = try boringSSLPKCS12Bundle(base64EncodedString: base64EncodedString)
    var pkey: UnsafeMutablePointer<EVP_PKEY>? = nil
    var cert: OpaquePointer?/*<X509>*/ = nil
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
    
    let certStackSize = caCerts.map { CNIOBoringSSL_sk_X509_num($0) } ?? 0
    var certs = [OpaquePointer]()
    certs.reserveCapacity(Int(certStackSize) + 1)
    certs.append(actualCert)
    
    for idx in 0..<certStackSize {
        guard let stackCertPtr = CNIOBoringSSL_sk_X509_value(caCerts, idx) else {
            preconditionFailure("Unable to get cert \(idx) from stack \(String(describing: caCerts))")
        }
        certs.append(stackCertPtr)
    }
    
    return (certs, actualKey)
}

extension Collection where Element == UInt8 {
    /// Provides a contiguous copy of the bytes of this collection in a heap-allocated
    /// memory region that is locked into memory (that is, which can never be backed by a file),
    /// and which will be scrubbed and freed after use, and which is null-terminated.
    ///
    /// This method should be used when it is necessary to take a secure copy of a collection of
    /// bytes. Its implementation relies on BoringSSL directly.
    func withSecureCString<T>(_ block: (UnsafePointer<Int8>) throws -> T) throws -> T {
        // We need to allocate some memory and prevent it being swapped to disk while we use it.
        // For that reason we use mlock.
        let bufferSize = Int(self.count) + 1
        let bufferPtr = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: bufferSize)
        defer {
            bufferPtr.deallocate()
        }
        
        try Posix.mlock(addr: bufferPtr.baseAddress!, len: bufferPtr.count)
        defer {
            // If munlock fails take out the process.
            try! Posix.munlock(addr: bufferPtr.baseAddress!, len: bufferPtr.count)
        }
        
        let (_, nextIndex) = bufferPtr.initialize(from: self)
        assert(nextIndex == (bufferPtr.endIndex - 1))
        
        // Add a null terminator.
        bufferPtr[nextIndex] = 0
        
        defer {
            // We use OpenSSL_cleanse here because the compiler can't optimize this away.
            // .initialize(repeating: 0) can be, and empirically is, optimized away, bzero
            // is deprecated, memset_s is not well supported cross-platform, and memset-to-zero
            // is famously easily optimised away. This is our best bet.
            CNIOBoringSSL_OPENSSL_cleanse(bufferPtr.baseAddress!, bufferPtr.count)
            bufferPtr.baseAddress!.deinitialize(count: bufferPtr.count)
        }
        
        // Ok, the memory is ready for use. Call the user.
        return try bufferPtr.withMemoryRebound(to: Int8.self) {
            try block($0.baseAddress!)
        }
    }
}

extension Optional where Wrapped: Collection, Wrapped.Element == UInt8 {
    func withSecureCString<T>(_ block: (UnsafePointer<Int8>?) throws -> T) throws -> T {
        if let `self` = self {
            return try self.withSecureCString({ try block($0) })
        } else {
            return try block(nil)
        }
    }
}
