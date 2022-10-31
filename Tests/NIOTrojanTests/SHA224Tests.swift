//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2021 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import PrettyBytes
import XCTest

@testable import NIOTrojan

// A testing utility that creates one contiguous and one discontiguous representation of the given Data.
extension Data {
    func asDataProtocols() -> (contiguous: Data, discontiguous: DispatchData) {
        guard self.count > 0 else {
            // We can't really have discontiguous options here, so we just return empty versions
            // of both.
            return (Data(), DispatchData.empty)
        }

        let contiguous = Data(self)
        let discontiguous: DispatchData = self.withUnsafeBytes { bytesPointer in
            let pivot = bytesPointer.count / 2
            var data = DispatchData.empty
            data.append(
                DispatchData(bytes: UnsafeRawBufferPointer(rebasing: bytesPointer[..<pivot]))
            )
            data.append(
                DispatchData(bytes: UnsafeRawBufferPointer(rebasing: bytesPointer[pivot...]))
            )
            return data
        }

        return (contiguous: contiguous, discontiguous: discontiguous)
    }
}

class SHA224Tests: XCTestCase {

    func assertHashFunctionWithVector<H: HashFunction>(
        hf: H.Type,
        data: Data,
        testVector: String,
        file: StaticString = (#file),
        line: UInt = #line
    ) throws {
        var h = hf.init()
        h.update(data: data)
        let result = h.finalize()

        let testBytes = try Data(hexString: testVector)

        XCTAssertEqual(testBytes, Data(result), file: file, line: line)
        XCTAssertEqual(Data(H.hash(data: data)), testBytes, file: file, line: line)

        let (contiguousResult, discontiguousResult) = testBytes.asDataProtocols()
        XCTAssert(result == contiguousResult, file: file, line: line)
        XCTAssert(result == discontiguousResult, file: file, line: line)
        XCTAssertFalse(result == DispatchData.empty, file: file, line: line)
    }

    func testSHA224HashFunction() throws {
        let data =
            ("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
                .data(using: String.Encoding.ascii)!)

        let testVector = "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3"

        try assertHashFunctionWithVector(hf: SHA224.self, data: data, testVector: testVector)

        let nullTestVector = "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        try assertHashFunctionWithVector(hf: SHA224.self, data: .init(), testVector: nullTestVector)
    }

    func testSHA224FunctionImplementCoW() {
        var hf = SHA224()
        hf.update(data: [1, 2, 3, 4])

        var hfCopy = hf
        hf.update(data: [5, 6, 7, 8])
        let digest = hf.finalize()

        hfCopy.update(data: [5, 6, 7, 8])
        let copyDigest = hfCopy.finalize()

        XCTAssertEqual(digest, copyDigest)
    }
}
