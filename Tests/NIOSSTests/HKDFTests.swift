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

import PrettyBytes
import XCTest

@testable import NIOSS

final class HKDFTests: XCTestCase {

    func testHKDFWorks() {
        let salt = "salt".data(using: .utf8)!

        let testable = [
            ("zpeU12da8J", "d54d5ac744147e0b509103037c13ed88378c9949eddc319242e73d05ca4e0811"),
            ("qfZ6UvBisY", "83bd95b7b359f3f02985602cf358f2577230cac1d53b86c6467948666393b2f1"),
            ("qlNrQlO3T4", "835e6ee996fabf1951849917b952ddcad925b0e028f026ae015807afce53343b"),
            ("0kNEtsgc3B", "a211c74bc464b36c66e0bf18d8cd033f2a382a6d9709a0937e87161afa0842aa"),
            ("oFiepZOAGh", "261575ed8d5b995706d054d0ad0b64650e7ce54a8cf3ea3ca4228253b4599392"),
        ]

        testable.forEach { k, expected in
            hkdfDerivedSymmetricKey(secretKey: k, salt: salt, outputByteCount: 32).withUnsafeBytes {
                XCTAssertEqual($0.hexString, expected)
            }
        }
    }
}
