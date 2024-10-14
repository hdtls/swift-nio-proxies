//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2023 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import XCTest

@testable import NEVMESS

final class FNVTests: XCTestCase {

  func testFNV1a32Checksum() {
    XCTAssertEqual(FNV1a32.hash(data: Array("028318abc1824029138141a2".utf8)), 1_797_177_856)
    XCTAssertEqual(FNV1a32.hash(data: Array("921d2507fa8007b7bd067d34".utf8)), 2_179_437_624)
    XCTAssertEqual(FNV1a32.hash(data: Array("0432bc49ac34412081288127".utf8)), 1_751_479_875)
    XCTAssertEqual(FNV1a32.hash(data: Array("438a547a94ea88dce46c6c85".utf8)), 911_518_110)
    XCTAssertEqual(FNV1a32.hash(data: Array("b30c084727ad1c592ac21d12".utf8)), 3_166_953_508)
    XCTAssertEqual(FNV1a32.hash(data: Array("b5e006ded553110e6dc56529".utf8)), 191_308_860)
  }
}
