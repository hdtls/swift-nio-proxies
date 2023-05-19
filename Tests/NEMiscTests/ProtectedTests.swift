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

import NIOConcurrencyHelpers
import XCTest

@testable import NEMisc

final class ProtectedTests: XCTestCase {

  @Protected var collection: [Int] = []
  @Protected var protected = ""

  let iterations = 1000

  func testReadWrite() throws {
    let protected = Protected("")

    DispatchQueue.concurrentPerform(iterations: iterations) { i in
      _ = protected.wrappedValue
      protected.wrappedValue = "\(i)"
    }
    XCTAssertNotEqual(protected.wrappedValue, "")
  }

  func testPropertyWrapperReadWrite() {
    DispatchQueue.concurrentPerform(iterations: iterations) { i in
      _ = protected
      protected = "\(i)"
    }
    XCTAssertNotEqual(protected, "")
  }

  func testReadWriteAPI() {
    DispatchQueue.concurrentPerform(iterations: iterations) { i in
      _ = $protected.read { $0 }
      $protected.write { $0 = "\(i)" }

      _ = $collection.read { $0 }
      $collection.write {
        $0.append(i)
      }
    }
    XCTAssertNotEqual(protected, "")
    XCTAssertEqual(collection.count, iterations)
  }

  func testAppendElementForRangeReplaceableCollection() {
    DispatchQueue.concurrentPerform(iterations: iterations) { i in
      $collection.append(i)
    }
    XCTAssertEqual(collection.count, iterations)
  }

  func testAppendElements() {
    DispatchQueue.concurrentPerform(iterations: iterations) { i in
      $collection.append(contentsOf: CollectionOfOne(i))
    }
    XCTAssertEqual(collection.count, iterations)
  }

  func testInsertElementAtIndex() {
    DispatchQueue.concurrentPerform(iterations: iterations) { i in
      $collection.insert(i, at: collection.count)
    }
    XCTAssertEqual(collection.count, iterations)
  }

  func testInsertElements() {
    DispatchQueue.concurrentPerform(iterations: iterations) { i in
      $collection.insert(contentsOf: CollectionOfOne(i), at: collection.count)
    }
    XCTAssertEqual(collection.count, iterations)
  }

  func testRemoveElementAtIndex() {
    let lock = NIOLock()
    collection = Array(repeating: 0, count: iterations)
    var position = 0
    DispatchQueue.concurrentPerform(iterations: iterations) { i in
      lock.withLock {
        position += 1
        $collection.remove(at: iterations - position)
      }
    }
    XCTAssertTrue(collection.isEmpty)
  }

  func testRemoveFirst() {
    collection = Array(repeating: 0, count: iterations)
    DispatchQueue.concurrentPerform(iterations: iterations) { _ in
      $collection.removeFirst()
    }
    XCTAssertTrue(collection.isEmpty)
  }

  func testRemoveFirstN() {
    collection = Array(repeating: 0, count: iterations)
    DispatchQueue.concurrentPerform(iterations: iterations) { _ in
      $collection.removeFirst(1)
    }
    XCTAssertTrue(collection.isEmpty)
  }

  func testRemoveAll() {
    collection = [1]
    DispatchQueue.concurrentPerform(iterations: iterations) { _ in
      $collection.removeAll(keepingCapacity: false)
    }
    XCTAssertTrue(collection.isEmpty)
  }

  func testRemoveAllWhere() {
    collection = [1, 2, 1, 3]
    DispatchQueue.concurrentPerform(iterations: iterations) { _ in
      $collection.removeAll { $0 == 1 }
    }
    XCTAssertEqual(collection, [2, 3])
  }

  func testFirstWhere() {
    XCTAssertNil($collection.first(where: { $0 == 1 }))

    collection = [1, 2, 1]
    XCTAssertEqual($collection.first(where: { $0 == 1 }), 1)
  }
}
