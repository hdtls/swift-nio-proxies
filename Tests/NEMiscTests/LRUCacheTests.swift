//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2023 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NEMisc
import XCTest

final class LRUCacheTests: XCTestCase {

  func testRemoveValue() {
    let cache = LRUCache<Int, Int>(capacity: 5)
    XCTAssertTrue(cache.isEmpty)
    cache.setValue(0, forKey: 0)
    cache.setValue(1, forKey: 1)
    XCTAssertEqual(cache.removeValue(forKey: 0), 0)
    XCTAssertEqual(cache.count, 1)
    XCTAssertFalse(cache.isEmpty)
    XCTAssertNil(cache.removeValue(forKey: 0))
    cache.setValue(nil, forKey: 1)
    XCTAssertTrue(cache.isEmpty)
  }

  func testRemoveAllValues() {
    let cache = LRUCache<Int, Int>(capacity: 2)
    cache.setValue(0, forKey: 0)
    cache.setValue(1, forKey: 1)
    cache.removeAllValues()
    XCTAssertTrue(cache.isEmpty)
    cache.setValue(0, forKey: 0)
    XCTAssertEqual(cache.count, 1)
  }

  func testGetValue() {
    let cache = LRUCache<Int, Int>(capacity: 2)
    cache.setValue(0, forKey: 0)
    cache.setValue(1, forKey: 1)
    XCTAssertEqual(cache.value(forKey: 0), 0)
    XCTAssertEqual(cache.value(forKey: 1), 1)
    XCTAssertNil(cache.value(forKey: 2))
  }

  func testInsertionPerformance() {
    let iterations = 10_000
    measure {
      let cache = LRUCache<Int, Int>(capacity: iterations)
      for i in 0..<iterations {
        cache.setValue(i, forKey: i)
      }
    }
  }

  func testRemovalPerformance() {
    let iterations = 10_000
    let cache = LRUCache<Int, Int>(capacity: iterations)
    for i in 0..<iterations {
      cache.setValue(i, forKey: i)
    }
    measure {
      for i in 0..<iterations {
        cache.removeValue(forKey: i)
      }
    }
  }

  func testLookupPerformance() {
    let iterations = 10_000
    let cache = LRUCache<Int, Int>(capacity: iterations)
    for i in 0..<iterations {
      cache.setValue(i, forKey: i)
    }
    measure {
      for i in 0..<iterations {
        _ = cache.value(forKey: i)
      }
    }
  }
}
