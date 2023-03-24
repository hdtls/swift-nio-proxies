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

@testable import NECore

final class DispathTimeTests: XCTestCase {

  let t1 = DispatchTime(uptimeNanoseconds: 0)

  func testDistanceWorks() {
    let t2 = DispatchTime(uptimeNanoseconds: 1)
    XCTAssertEqual(t1.distance(to: t2), .nanoseconds(1))
  }

  func testDispathTimeIntervalPrettyPrintedWorks() {
    var t2 = DispatchTime(uptimeNanoseconds: 1)
    XCTAssertEqual(t1.distance(to: t2).prettyPrinted, "1 ns")

    t2 = DispatchTime(uptimeNanoseconds: 1_000)
    var t3 = DispatchTime(uptimeNanoseconds: 999)
    XCTAssertEqual(t1.distance(to: t2).prettyPrinted, "1 µs")
    XCTAssertEqual(t1.distance(to: t3).prettyPrinted, "999 ns")

    t2 = DispatchTime(uptimeNanoseconds: 1_000_000)
    t3 = DispatchTime(uptimeNanoseconds: 999_999)
    XCTAssertEqual(t1.distance(to: t2).prettyPrinted, "1 ms")
    XCTAssertEqual(t1.distance(to: t3).prettyPrinted, "999 µs")

    t2 = DispatchTime(uptimeNanoseconds: 1_000_000_000)
    t3 = DispatchTime(uptimeNanoseconds: 999_999_999)
    XCTAssertEqual(t1.distance(to: t2).prettyPrinted, "1 s")
    XCTAssertEqual(t1.distance(to: t3).prettyPrinted, "999 ms")
  }
}
