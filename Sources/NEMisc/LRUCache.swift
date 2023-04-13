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

public struct LRUCache<Key, Value> where Key: Hashable {

  private var entries: [Key: CacheEntry] = [:]

  private var head: CacheEntry?

  private var tail: CacheEntry?

  /// The maximum number of values permitted
  private let capacity: Int

  /// The number of values currently stored in the cache
  public var count: Int {
    entries.count
  }

  /// A boolean value to determine whether the cache is empty.
  public var isEmpty: Bool {
    entries.isEmpty
  }

  /// Initialize an instance of `LRUCache` with specified `capacity`.
  public init(capacity: Int) {
    self.capacity = capacity
    entries.reserveCapacity(capacity)
  }

  /// Set or remove cached value for specified key.
  ///
  /// Remove value from caches if value is `nil` else set new value for key.
  public mutating func setValue(_ value: Value?, forKey key: Key) {
    guard let value = value else {
      removeValue(forKey: key)
      return
    }

    if let entry = entries[key] {
      entry.value = value
      remove(entry)
      append(entry)
    } else {
      let entry = CacheEntry(key: key, value: value)
      entries[key] = entry
      append(entry)
    }
    clean()
  }

  /// Remove a value  from the cache and return it
  @discardableResult
  public mutating func removeValue(forKey key: Key) -> Value? {
    guard let entry = entries.removeValue(forKey: key) else {
      return nil
    }
    remove(entry)
    return entry.value
  }

  /// Fetch a value from the cache
  public mutating func value(forKey key: Key) -> Value? {
    if let entry = entries[key] {
      remove(entry)
      append(entry)
      return entry.value
    }
    return nil
  }

  /// Remove all values from the cache
  public mutating func removeAllValues() {
    entries.removeAll()
    head = nil
    tail = nil
  }
}

extension LRUCache {

  final fileprivate class CacheEntry {

    let key: Key

    var value: Value

    var prev: CacheEntry?

    var next: CacheEntry?

    init(key: Key, value: Value) {
      self.key = key
      self.value = value
    }
  }

  fileprivate mutating func remove(_ entry: CacheEntry) {
    if head === entry {
      head = entry.next
    }
    if tail === entry {
      tail = entry.prev
    }
    entry.next?.prev = entry.prev
    entry.prev?.next = entry.next
    entry.next = nil
  }

  fileprivate mutating func append(_ entry: CacheEntry) {
    assert(entry.next == nil)
    if head == nil {
      head = entry
    }
    entry.prev = tail
    tail?.next = entry
    tail = entry
  }

  fileprivate mutating func clean() {
    while count > capacity, let entry = head {
      remove(entry)
      entries.removeValue(forKey: entry.key)
    }
  }
}
