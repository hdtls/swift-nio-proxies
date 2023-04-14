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
public struct Protected<T> {

  private let lock = NIOLock()
  private var value: T

  public init(_ value: T) {
    self.value = value
  }

  /// The contained value. Unsafe for anything more than direct read or write.
  public var wrappedValue: T {
    get { lock.withLock { value } }
    set { lock.withLock { value = newValue } }
  }

  public var projectedValue: Protected<T> { self }

  public init(wrappedValue: T) {
    value = wrappedValue
  }

  /// Synchronously read or transform the contained value.
  ///
  /// - Parameter closure: The closure to execute.
  ///
  /// - Returns:           The return value of the closure passed.
  public func read<U>(_ closure: (T) -> U) -> U {
    lock.withLock { closure(self.value) }
  }

  /// Synchronously modify the protected value.
  ///
  /// - Parameter closure: The closure to execute.
  ///
  /// - Returns:           The modified value.
  @discardableResult
  public mutating func write<U>(_ closure: (inout T) -> U) -> U {
    lock.withLock { closure(&self.value) }
  }

  public subscript<Property>(dynamicMember keyPath: WritableKeyPath<T, Property>) -> Property {
    get { lock.withLock { value[keyPath: keyPath] } }
    set { lock.withLock { value[keyPath: keyPath] = newValue } }
  }
}

extension Protected: Sendable where T: Sendable {}

extension Protected where T: RangeReplaceableCollection {
  /// Adds a new element to the end of this protected collection.
  ///
  /// - Parameter newElement: The `Element` to append.
  public mutating func append(_ newElement: T.Element) {
    write { (ward: inout T) in
      ward.append(newElement)
    }
  }

  /// Adds the elements of a sequence to the end of this protected collection.
  ///
  /// - Parameter newElements: The `Sequence` to append.
  public mutating func append<S: Sequence>(contentsOf newElements: S)
  where S.Element == T.Element {
    write { (ward: inout T) in
      ward.append(contentsOf: newElements)
    }
  }

  /// Add the elements of a collection to the end of the protected collection.
  ///
  /// - Parameter newElements: The `Collection` to append.
  public mutating func append<C: Collection>(contentsOf newElements: C)
  where C.Element == T.Element {
    write { (ward: inout T) in
      ward.append(contentsOf: newElements)
    }
  }
}
