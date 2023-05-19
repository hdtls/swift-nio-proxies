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

  let iterations = 1000

  func testRemoveValue() {
    var cache = LRUCache<Int, Int>(capacity: 5)
    XCTAssertTrue(cache.isEmpty)
    cache.setValue(0, forKey: 0)
    cache.setValue(1, forKey: 1)
    XCTAssertEqual(cache.removeValue(forKey: 0), 0)
    XCTAssertEqual(cache.count, 1)
    XCTAssertFalse(cache.isEmpty)
    XCTAssertNil(cache.removeValue(forKey: 0))
    cache.setValue(nil, forKey: 1)
    XCTAssertTrue(cache.isEmpty)

    cache = LRUCache(capacity: iterations)
    for i in 0..<iterations {
      cache.setValue(i, forKey: i)
    }
    DispatchQueue.concurrentPerform(iterations: iterations) { i in
      cache.removeValue(forKey: i)
    }
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

    DispatchQueue.concurrentPerform(iterations: iterations) { _ in
      cache.setValue(1, forKey: 1)
      cache.removeAllValues()
    }

    XCTAssertTrue(cache.isEmpty)
  }

  func testGetValue() {
    let cache = LRUCache<Int, Int>(capacity: 2)
    cache.setValue(0, forKey: 0)
    cache.setValue(1, forKey: 1)
    XCTAssertEqual(cache.value(forKey: 0), 0)
    XCTAssertEqual(cache.value(forKey: 1), 1)
    XCTAssertNil(cache.value(forKey: 2))
  }

  func testSetValueForKey() {
    var cache = LRUCache<Int, Int>(capacity: 2)
    cache.setValue(0, forKey: 0)
    cache.setValue(1, forKey: 1)
    cache.setValue(2, forKey: 2)
    cache.setValue(2, forKey: 2)
    cache.setValue(0, forKey: 0)
    cache.setValue(0, forKey: 0)
    cache.setValue(1, forKey: 1)

    XCTAssertEqual(cache.count, 2)
    XCTAssertEqual(cache.value(forKey: 0), 0)
    XCTAssertEqual(cache.value(forKey: 1), 1)
    XCTAssertNil(cache.value(forKey: 2))

    cache = LRUCache(capacity: iterations)
    DispatchQueue.concurrentPerform(iterations: iterations) { i in
      cache.setValue(i, forKey: i)
    }
    XCTAssertEqual(cache.count, iterations)
  }

  func testInsertionPerformance() {
    let iterations = 10_000
    measure {
      let cache = LRUCache<Int, Int>(capacity: iterations / 2)
      for i in 0..<iterations {
        cache.setValue(Int.random(in: 0...iterations), forKey: i)
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
