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

// THIS FILE IS MOSTLY COPIED FROM [swift-crypto](https://github.com/apple/swift-crypto)

@_implementationOnly import CSHAKE128

protocol HashFunctionImplementationDetails: HashFunction where Digest: DigestPrivate {}

struct OpenSSLDigestImpl<H: HashFunctionImplementationDetails> {
    private var context: DigestContext

    init() {
        self.context = DigestContext()
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

    internal func read(digestSize: Int) -> H.Digest {
        // To have a non-destructive finalize operation we must allocate.
        let copyContext = self.context
        let digestBytes = copyContext.read(digestSize: digestSize)
        return digestBytes.withUnsafeBytes {
            // We force unwrap here because if the digest size is wrong it's an internal error.
            H.Digest(bufferPointer: $0)!
        }
    }
}

class DigestContext {

    private var contextPointer: UnsafeMutablePointer<CSHAKE128.sha3_ctx_t>

    init() {
        // We force unwrap because we cannot recover from allocation failure.
        self.contextPointer = UnsafeMutablePointer<CSHAKE128.sha3_ctx_t>.allocate(
            capacity: MemoryLayout<CSHAKE128.sha3_ctx_t>.size
        )
        self.contextPointer.initialize(to: .init())

        CSHAKE128_shake128_init(self.contextPointer)
    }

    init(copying original: DigestContext) {
        // We force unwrap because we cannot recover from allocation failure.
        self.contextPointer = UnsafeMutablePointer<CSHAKE128.sha3_ctx_t>.allocate(
            capacity: MemoryLayout<CSHAKE128.sha3_ctx_t>.size
        )
        self.contextPointer.initialize(to: original.contextPointer.pointee)
    }

    func update(data: UnsafeRawBufferPointer) {
        guard let baseAddress = data.baseAddress else {
            return
        }
        CSHAKE128_shake_update(self.contextPointer, baseAddress, data.count)
        CSHAKE128_shake_xof(self.contextPointer)
    }

    func read(digestSize: Int) -> [UInt8] {
        var digestBytes = Array(repeating: UInt8(0), count: Int(digestSize))

        digestBytes.withUnsafeMutableBytes { digestPointer in
            assert(digestPointer.count == digestSize)
            CSHAKE128_shake_read(self.contextPointer, digestPointer.baseAddress, digestSize)
        }

        return digestBytes
    }

    // This finalize function is _destructive_: do not call it if you want to reuse the object!
    func finalize() -> [UInt8] {
        let digestSize = 16
        var digestBytes = Array(repeating: UInt8(0), count: Int(digestSize))

        digestBytes.withUnsafeMutableBytes { digestPointer in
            assert(digestPointer.count == digestSize)
            CSHAKE128_shake_read(self.contextPointer, digestPointer.baseAddress, digestSize)
        }

        return digestBytes
    }

    deinit {
        self.contextPointer.deinitialize(count: MemoryLayout<CSHAKE128.sha3_ctx_t>.size)
        self.contextPointer.deallocate()
    }
}
