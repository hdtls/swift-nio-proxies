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

import XCTest

@testable import NetbotVMESS
@testable import SHAKE128

class ByteBufferTests: XCTestCase {

    func testWriteAddress() throws {
        var buffer = ByteBuffer()
        buffer.writeAddress(.domainPort("www.v2fly.org", 443))
        buffer.withUnsafeReadableBytes {
            XCTAssertEqual($0.hexString, "01bb020d7777772e7632666c792e6f7267")
        }
    }
}
