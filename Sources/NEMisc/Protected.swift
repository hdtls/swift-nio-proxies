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

import NIOConcurrencyHelpers

/// A thread-safe wrapper around a value.
@propertyWrapper
@dynamicMemberLookup
final public class Protected<Value> {

  private let lock = NIOLock()
  private var value: Value

  public init(_ value: Value) {
    self.value = value
  }

  /// The contained value. Unsafe for anything more than direct read or write.
  public var wrappedValue: Value {
    get { lock.withLock { value } }
    set { lock.withLock { value = newValue } }
  }

  public var projectedValue: Protected<Value> { self }

  public init(wrappedValue: Value) {
    value = wrappedValue
  }

  /// Synchronously read or transform the contained value.
  ///
  /// - Parameter closure: The closure to execute.
  ///
  /// - Returns:           The return value of the closure passed.
  public func read<U>(_ closure: (Value) throws -> U) rethrows -> U {
    try lock.withLock { try closure(self.value) }
  }

  /// Synchronously modify the protected value.
  ///
  /// - Parameter closure: The closure to execute.
  ///
  /// - Returns:           The modified value.
  @discardableResult
  public func write<U>(_ closure: (inout Value) throws -> U) rethrows -> U {
    try lock.withLock { try closure(&self.value) }
  }

  public subscript<Property>(dynamicMember keyPath: WritableKeyPath<Value, Property>) -> Property {
    get { lock.withLock { value[keyPath: keyPath] } }
    set { lock.withLock { value[keyPath: keyPath] = newValue } }
  }

  public subscript<Property>(dynamicMember keyPath: KeyPath<Value, Property>) -> Property {
    lock.withLock { value[keyPath: keyPath] }
  }
}

extension Protected: @unchecked Sendable where Value: Sendable {}

extension Protected where Value: RangeReplaceableCollection {
  /// Adds a new element to the end of this protected collection.
  ///
  /// - Parameter newElement: The `Element` to append.
  public func append(_ newElement: Value.Element) {
    write { $0.append(newElement) }
  }

  /// Adds the elements of a sequence to the end of this protected collection.
  ///
  /// - Parameter newElements: The `Sequence` to append.
  public func append<S: Sequence>(contentsOf newElements: S) where S.Element == Value.Element {
    write { $0.append(contentsOf: newElements) }
  }

  /// Inserts a new element into the collection at the specified position.
  ///
  /// - Parameter newElement: The new element to insert into the collection.
  /// - Parameter i: The position at which to insert the new element.
  ///   `index` must be a valid index into the collection.
  public func insert(_ newElement: Value.Element, at i: Value.Index) {
    write { $0.insert(newElement, at: i) }
  }

  /// Inserts the elements of a sequence into the collection at the specified
  /// position.
  ///
  /// - Parameter newElements: The new elements to insert into the collection.
  /// - Parameter i: The position at which to insert the new elements. `index`
  ///   must be a valid index of the collection.
  public func insert<S>(contentsOf newElements: S, at i: Value.Index)
  where S: Collection, Value.Element == S.Element {
    write { $0.insert(contentsOf: newElements, at: i) }
  }

  /// Removes and returns the element at the specified position.
  ///
  /// - Parameter i: The position of the element to remove. `index` must be
  ///   a valid index of the collection that is not equal to the collection's
  ///   end index.
  /// - Returns: The removed element.
  @discardableResult public func remove(at i: Value.Index) -> Value.Element {
    write { $0.remove(at: i) }
  }

  /// Removes and returns the first element of the collection.
  ///
  /// The collection must not be empty.
  ///
  /// - Returns: The removed element.
  @discardableResult public func removeFirst() -> Value.Element {
    write { $0.removeFirst() }
  }

  /// Removes the specified number of elements from the beginning of the
  /// collection.
  ///
  /// - Parameter k: The number of elements to remove from the collection.
  ///   `k` must be greater than or equal to zero and must not exceed the
  ///   number of elements in the collection.
  public func removeFirst(_ k: Int) {
    write { $0.removeFirst(k) }
  }

  /// Removes all elements from the collection.
  ///
  /// - Parameter keepCapacity: Pass `true` to request that the collection
  ///   avoid releasing its storage. Retaining the collection's storage can
  ///   be a useful optimization when you're planning to grow the collection
  ///   again. The default value is `false`.
  public func removeAll(keepingCapacity keepCapacity: Bool) {
    write { $0.removeAll(keepingCapacity: keepCapacity) }
  }

  /// Removes all the elements that satisfy the given predicate.
  ///
  /// - Parameter shouldBeRemoved: A closure that takes an element of the
  ///   sequence as its argument and returns a Boolean value indicating
  ///   whether the element should be removed from the collection.
  ///
  /// - Complexity: O(*n*), where *n* is the length of the collection.
  public func removeAll(where shouldBeRemoved: (Value.Element) throws -> Bool) rethrows {
    try write { try $0.removeAll(where: shouldBeRemoved) }
  }
}

extension Protected where Value: Sequence {

  public func first(where predicate: (Value.Element) throws -> Bool) rethrows -> Value.Element? {
    try read { try $0.first(where: predicate) }
  }
}
