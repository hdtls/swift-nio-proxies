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

import NETestUtils
import NIOCore
import SHAKE128
import XCTest

@testable import NIOVMESS

class ByteBufferTests: XCTestCase {

    func testWriteAddress() throws {
        var buffer = ByteBuffer()
        buffer.writeAddress(.domainPort(host: "www.v2fly.org", port: 443))
        buffer.withUnsafeReadableBytes {
            XCTAssertEqual($0.hexString, "01bb020d7777772e7632666c792e6f7267")
        }
    }
}
