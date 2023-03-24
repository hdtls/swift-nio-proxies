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

import XCTest

@testable import NEVMESS

final class CRCChecksumTests: XCTestCase {

  func testCRC32Checksum() {
    XCTAssertEqual(CRC32.checksum("1457b5bb9ffce04b".utf8), 3_630_314_476)
    XCTAssertEqual(CRC32.checksum("065e3dec5356d1a8".utf8), 4_122_247_039)
    XCTAssertEqual(CRC32.checksum("7911226774d08440".utf8), 2_071_897_217)
    XCTAssertEqual(CRC32.checksum("60c2de912227c88b".utf8), 2_803_390_074)
    XCTAssertEqual(CRC32.checksum("813e73491b302f61".utf8), 1_427_083_490)
  }
}
