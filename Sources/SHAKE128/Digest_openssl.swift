//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2022 Junfeng Zhang. and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

@_implementationOnly import COpenSSLCrypto

protocol HashFunctionImplementationDetails: HashFunction where Digest: DigestPrivate {}

protocol BoringSSLBackedHashFunction: HashFunctionImplementationDetails {
    static var digestType: DigestContext.DigestType { get }
}

extension SHAKE128: BoringSSLBackedHashFunction {
    static var digestType: DigestContext.DigestType {
        return .shake128
    }
}

struct OpenSSLDigestImpl<H: BoringSSLBackedHashFunction> {
    private var context: DigestContext
    
    init() {
        self.context = DigestContext(digest: H.digestType)
    }
    
    internal mutating func update(data: UnsafeRawBufferPointer) {
        if !isKnownUniquelyReferenced(&self.context) {
            self.context = DigestContext(copying: self.context)
        }
        self.context.update(data: data)
    }
    
    internal func finalize() -> H.Digest {
        // To have a non-destructive finalize operation we must allocate.
        let copyContext = DigestContext(copying: self.context)
        let digestBytes = copyContext.finalize()
        return digestBytes.withUnsafeBytes {
            // We force unwrap here because if the digest size is wrong it's an internal error.
            H.Digest(bufferPointer: $0)!
        }
    }
}

class DigestContext {
//    private var contextPointer: UnsafeMutablePointer<COpenSSLCrypto.EVP_MD_CTX>
    private var contextPointer: OpaquePointer

    init(digest: DigestType) {
        // We force unwrap because we cannot recover from allocation failure.
        self.contextPointer = COpenSSLCrypto.EVP_MD_CTX_new()!
        guard COpenSSLCrypto.EVP_DigestInit(self.contextPointer, digest.dispatchTable) != 0 else {
            // We can't do much but crash here.
            fatalError("Unable to initialize digest state: \(COpenSSLCrypto.ERR_get_error())")
        }
    }
    
    init(copying original: DigestContext) {
        // We force unwrap because we cannot recover from allocation failure.
        self.contextPointer = COpenSSLCrypto.EVP_MD_CTX_new()!
        guard COpenSSLCrypto.EVP_MD_CTX_copy(self.contextPointer, original.contextPointer) != 0 else {
            // We can't do much but crash here.
            fatalError("Unable to copy digest state: \(COpenSSLCrypto.ERR_get_error())")
        }
    }
    
    func update(data: UnsafeRawBufferPointer) {
        guard let baseAddress = data.baseAddress else {
            return
        }
        
        COpenSSLCrypto.EVP_DigestUpdate(self.contextPointer, baseAddress, data.count)
    }
    
    // This finalize function is _destructive_: do not call it if you want to reuse the object!
    func finalize() -> [UInt8] {
//        let digestSize = COpenSSLCrypto.EVP_MD_size(self.contextPointer.pointee.digest)
        let digestSize = 16
        var digestBytes = Array(repeating: UInt8(0), count: Int(digestSize))
        var count = UInt32(digestSize)
        
        digestBytes.withUnsafeMutableBufferPointer { digestPointer in
            assert(digestPointer.count == count)
            COpenSSLCrypto.EVP_DigestFinal(self.contextPointer, digestPointer.baseAddress, &count)
        }
        
        return digestBytes
    }
    
    deinit {
        COpenSSLCrypto.EVP_MD_CTX_free(self.contextPointer)
    }
}

extension DigestContext {
    struct DigestType {
        var dispatchTable: OpaquePointer
        
        private init(_ dispatchTable: OpaquePointer) {
            self.dispatchTable = dispatchTable
        }
        
        static let shake128 = DigestType(COpenSSLCrypto.EVP_shake128())
    }
}
