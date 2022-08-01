//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2021 Junfeng Zhang. and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation

public actor LRUCache<Key: Hashable, Value> {

    private var entries: [Key: CacheEntry] = [:]

    private unowned(unsafe) var head: CacheEntry?

    private unowned(unsafe) var tail: CacheEntry?

    /// The current total cost of values in the cache
    public private(set) var totalCost: Int = 0

    /// The maximum total cost permitted
    public var totalCostLimit: Int {
        didSet { clean() }
    }

    /// The maximum number of values permitted
    public var capacity: Int {
        didSet { clean() }
    }

    /// Initialize an instance of `LRUCache` with specified `capacity` and `totalCostLimit`.
    public init(capacity: Int, totalCostLimit: Int = .max) {
        self.capacity = capacity
        self.totalCostLimit = totalCostLimit
    }
}

extension LRUCache {

    /// The number of values currently stored in the cache
    public var count: Int {
        entries.count
    }

    /// Is the cache empty?
    public var isEmpty: Bool {
        entries.isEmpty
    }

    /// Insert a value into the cache with optional `cost`
    public func setValue(_ value: Value?, forKey key: Key, cost: Int = 0) {
        guard let value = value else {
            removeValue(forKey: key)
            return
        }

        if let entry = entries[key] {
            entry.value = value
            totalCost -= entry.cost
            entry.cost = cost
            remove(entry)
            append(entry)
        } else {
            let entry = CacheEntry(
                value: value,
                cost: cost,
                key: key
            )
            entries[key] = entry
            append(entry)
        }
        totalCost += cost
        clean()
    }

    /// Remove a value  from the cache and return it
    @discardableResult
    public func removeValue(forKey key: Key) -> Value? {
        guard let entry = entries.removeValue(forKey: key) else {
            return nil
        }
        remove(entry)
        totalCost -= entry.cost
        return entry.value
    }

    /// Fetch a value from the cache
    public func value(forKey key: Key) -> Value? {
        if let entry = entries[key] {
            remove(entry)
            append(entry)
            return entry.value
        }
        return nil
    }

    /// Remove all values from the cache
    public func removeAllValues() {
        entries.removeAll()
        head = nil
        tail = nil
    }
}

extension LRUCache {

    final private class CacheEntry {

        var value: Value

        var cost: Int

        let key: Key

        unowned(unsafe) var prev: CacheEntry?

        unowned(unsafe) var next: CacheEntry?

        init(value: Value, cost: Int, key: Key) {
            self.value = value
            self.cost = cost
            self.key = key
        }
    }

    private func remove(_ entry: CacheEntry) {
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

    private func append(_ entry: CacheEntry) {
        assert(entry.next == nil)
        if head == nil {
            head = entry
        }
        entry.prev = tail
        tail?.next = entry
        tail = entry
    }

    private func clean() {
        while totalCost > totalCostLimit || count > capacity,
            let entry = head
        {
            remove(entry)
            entries.removeValue(forKey: entry.key)
            totalCost -= entry.cost
        }
    }
}
