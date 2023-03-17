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

//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

// THIS FILE IS MOSTLY COPIED FROM [swift-crypto](https://github.com/apple/swift-crypto)

// swift-format-ignore-file

import Foundation

#if !(os(macOS) || os(iOS) || os(watchOS) || os(tvOS))
typealias errno_t = CInt

// This is a Swift wrapper for the libc function that does not exist on Linux. We shim it via a call to OPENSSL_cleanse.
// We have the same syntax, but mostly ignore it.
@discardableResult
func memset_s(_ s: UnsafeMutableRawPointer!, _ smax: Int, _ byte: CInt, _ n: Int) -> errno_t {
    assert(smax == n, "memset_s invariant not met")
    assert(byte == 0, "memset_s used to not zero anything")

    #if os(Windows)
    SecureZeroMemory(s, smax)
    #else
    if smax != 0 {
        memset(s, 0, smax)
    }
    #endif
    return 0
}
#endif

public struct SecureBytes {
    @usableFromInline
    var backing: Backing

    @inlinable
    public init() {
        self = .init(count: 0)
    }

    public init(count: Int) {
        self.backing = SecureBytes.Backing.create(randomBytes: count)
    }

    public init<D: ContiguousBytes>(bytes: D) {
        self.backing = Backing.create(bytes: bytes)
    }

    /// Allows initializing a SecureBytes object with a closure that will initialize the memory.
    @usableFromInline
    init(
        unsafeUninitializedCapacity: Int,
        initializingWith callback: (inout UnsafeMutableRawBufferPointer, inout Int) throws -> Void
    ) rethrows {
        self.backing = Backing.create(capacity: unsafeUninitializedCapacity)
        try self.backing._withVeryUnsafeMutableBytes { veryUnsafePointer in
            // As Array does, we want to truncate the initializing pointer to only have the requested size.
            var veryUnsafePointer = UnsafeMutableRawBufferPointer(
                rebasing: veryUnsafePointer.prefix(unsafeUninitializedCapacity)
            )
            var initializedCount = 0
            try callback(&veryUnsafePointer, &initializedCount)

            self.backing.count = initializedCount
        }
    }
}

extension SecureBytes {

    public mutating func append<C: Collection>(_ data: C) where C.Element == UInt8 {
        let requiredCapacity = self.count + data.count
        if !isKnownUniquelyReferenced(&self.backing) || requiredCapacity > self.backing.capacity {
            let newBacking = Backing.create(capacity: requiredCapacity)
            newBacking._appendBytes(self.backing, inRange: 0..<self.count)
            self.backing = newBacking
        }
        self.backing._appendBytes(data)
    }

    public mutating func reserveCapacity(_ n: Int) {
        if self.backing.capacity >= n {
            return
        }

        let newBacking = Backing.create(capacity: n)
        newBacking._appendBytes(self.backing, inRange: 0..<self.count)
        self.backing = newBacking
    }
}

// MARK: - Equatable conformance, constant-time
extension SecureBytes: Equatable {

    public static func == (lhs: SecureBytes, rhs: SecureBytes) -> Bool {
        return safeCompare(lhs, rhs)
    }
}

// MARK: - Collection conformance
extension SecureBytes: Collection {

    public struct Index {
        /* fileprivate but usableFromInline */ @usableFromInline var offset: Int

        /*@inlinable*/ @usableFromInline internal init(offset: Int) {
            self.offset = offset
        }
    }

    @inlinable
    public var startIndex: Index {
        return Index(offset: 0)
    }

    @inlinable
    public var endIndex: Index {
        return Index(offset: self.count)
    }

    @inlinable
    public var count: Int {
        return self.backing.count
    }

    @inlinable
    public subscript(_ index: Index) -> UInt8 {
        get {
            return self.backing[offset: index.offset]
        }
        set {
            self.backing[offset: index.offset] = newValue
        }
    }

    @inlinable
    public func index(after index: Index) -> Index {
        return index.advanced(by: 1)
    }
}

// MARK: - BidirectionalCollection conformance
extension SecureBytes: BidirectionalCollection {
    @inlinable
    public func index(before index: Index) -> Index {
        return index.advanced(by: -1)
    }
}

// MARK: - RandomAccessCollection conformance
extension SecureBytes: RandomAccessCollection {}

// MARK: - MutableCollection conformance
extension SecureBytes: MutableCollection {}

// MARK: - RangeReplaceableCollection conformance
extension SecureBytes: RangeReplaceableCollection {
    @inlinable
    public mutating func replaceSubrange<C: Collection>(
        _ subrange: Range<Index>,
        with newElements: C
    ) where C.Element == UInt8 {
        let requiredCapacity = self.backing.count - subrange.count + newElements.count

        if !isKnownUniquelyReferenced(&self.backing) || requiredCapacity > self.backing.capacity {
            // We have to allocate anyway, so let's use a nice straightforward copy.
            let newBacking = Backing.create(capacity: requiredCapacity)

            let lowerSlice = 0..<subrange.lowerBound.offset
            let upperSlice = subrange.upperBound.offset..<self.count

            newBacking._appendBytes(self.backing, inRange: lowerSlice)
            newBacking._appendBytes(newElements)
            newBacking._appendBytes(self.backing, inRange: upperSlice)

            self.backing = newBacking
            return
        } else {
            // We have room, and a unique pointer. Ask the backing storage to shuffle around.
            let offsetRange = subrange.lowerBound.offset..<subrange.upperBound.offset
            self.backing.replaceSubrangeFittingWithinCapacity(offsetRange, with: newElements)
        }
    }
}

// MARK: - ContiguousBytes conformance
extension SecureBytes: ContiguousBytes {

    @inlinable
    public func withUnsafeBytes<T>(_ body: (UnsafeRawBufferPointer) throws -> T) rethrows -> T {
        return try self.backing.withUnsafeBytes(body)
    }

    @inlinable
    public mutating func withUnsafeMutableBytes<T>(
        _ body: (UnsafeMutableRawBufferPointer) throws -> T
    ) rethrows -> T {
        if !isKnownUniquelyReferenced(&self.backing) {
            self.backing = Backing.create(copying: self.backing)
        }

        return try self.backing.withUnsafeMutableBytes(body)
    }
}

// MARK: - DataProtocol conformance
extension SecureBytes: DataProtocol {
    @inlinable
    public var regions: CollectionOfOne<SecureBytes> {
        return CollectionOfOne(self)
    }
}

// MARK: - MutableDataProtocol conformance
extension SecureBytes: MutableDataProtocol {}

// MARK: - Index conformances
extension SecureBytes.Index: Hashable {}

extension SecureBytes.Index: Comparable {
    public static func < (lhs: SecureBytes.Index, rhs: SecureBytes.Index) -> Bool {
        return lhs.offset < rhs.offset
    }
}

extension SecureBytes.Index: Strideable {
    public func advanced(by n: Int) -> SecureBytes.Index {
        return SecureBytes.Index(offset: self.offset + n)
    }

    public func distance(to other: SecureBytes.Index) -> Int {
        return other.offset - self.offset
    }
}

// MARK: - Heap allocated backing storage.
extension SecureBytes {
    @usableFromInline
    internal struct BackingHeader {
        @usableFromInline
        internal var count: Int

        @usableFromInline
        internal var capacity: Int
    }

    @usableFromInline
    internal class Backing: ManagedBuffer<BackingHeader, UInt8> {
        @usableFromInline
        class func create(capacity: Int) -> Backing {
            let capacity = Int(UInt32(capacity).nextPowerOf2ClampedToMax())
            return Backing.create(
                minimumCapacity: capacity,
                makingHeaderWith: { _ in BackingHeader(count: 0, capacity: capacity) }
            ) as! Backing
        }

        @usableFromInline
        class func create(copying original: Backing) -> Backing {
            return Backing.create(bytes: original)
        }

        @inlinable
        class func create<D: ContiguousBytes>(bytes: D) -> Backing {
            return bytes.withUnsafeBytes { bytesPtr in
                let backing = Backing.create(capacity: bytesPtr.count)
                backing._withVeryUnsafeMutableBytes { targetPtr in
                    targetPtr.copyMemory(from: bytesPtr)
                }
                backing.count = bytesPtr.count
                precondition(backing.count <= backing.capacity)
                return backing
            }
        }

        @usableFromInline
        class func create(randomBytes: Int) -> Backing {
            let backing = Backing.create(capacity: randomBytes)
            backing._withVeryUnsafeMutableBytes { targetPtr in
                assert(targetPtr.count >= randomBytes)
                targetPtr.initializeWithRandomBytes(count: randomBytes)
            }
            backing.count = randomBytes
            return backing
        }

        deinit {
            // We always clear the whole capacity, even if we don't think we used it all.
            let bytesToClear = self.header.capacity

            _ = self.withUnsafeMutablePointerToElements { elementsPtr in
                memset_s(elementsPtr, bytesToClear, 0, bytesToClear)
            }
        }

        @usableFromInline
        var count: Int {
            get {
                return self.header.count
            }
            set {
                self.header.count = newValue
            }
        }

        @usableFromInline
        subscript(offset offset: Int) -> UInt8 {
            get {
                //precondition(offset >= 0 && offset < self.count)
                return self.withUnsafeMutablePointerToElements { return ($0 + offset).pointee }
            }
            set {
                //precondition(offset >= 0 && offset < self.count)
                return self.withUnsafeMutablePointerToElements { ($0 + offset).pointee = newValue }
            }
        }
    }
}

extension SecureBytes.Backing {

    @usableFromInline
    func replaceSubrangeFittingWithinCapacity<C: Collection>(
        _ subrange: Range<Int>,
        with newElements: C
    ) where C.Element == UInt8 {
        // This function is called when have a unique reference to the backing storage, and we have enough room to store these bytes without
        // any problem. We have one pre-existing buffer made up of 4 regions: a prefix set of bytes that are
        // before the range "subrange", a range of bytes to be replaced (R1), a suffix set of bytes that are after
        // the range "subrange" but within the valid count, and then a region of uninitialized memory. We also have
        // a new set of bytes, R2, that may be larger or smaller than R1, and could indeed be empty!
        //
        // ┌────────────────────────┬──────────────────┬──────────────────┬───────────────┐
        // │         Prefix         │        R1        │      Suffix      │ Uninitialized │
        // └────────────────────────┴──────────────────┴──────────────────┴───────────────┘
        //
        //                ┌─────────────────────────────────────┐
        //                │                  R2                 │
        //                └─────────────────────────────────────┘
        //
        // The minimal number of steps we can take in the general case is two steps. We can't just copy R2 into the space
        // for R1 and then move the suffix, as if R2 is larger than R1 we'll have thrown some suffix bytes away. So we have
        // to move suffix first. What we do is take the bytes in suffix, and move them (via memmove). We can then copy
        // R2 in, and feel confident that the space in memory is right.
        precondition(
            self.count - subrange.count + newElements.count <= self.capacity,
            "Insufficient capacity"
        )

        let moveDistance = newElements.count - subrange.count
        let suffixRange = subrange.upperBound..<self.count
        self._moveBytes(range: suffixRange, by: moveDistance)
        self._copyBytes(newElements, at: subrange.lowerBound)
        self.count += newElements.count - subrange.count
    }

    /// Appends the bytes of a collection to this storage, crashing if there is not enough room.
    @usableFromInline
    /* private but inlinable */ func _appendBytes<C: Collection>(_ bytes: C)
    where C.Element == UInt8 {
        let byteCount = bytes.count

        precondition(
            self.capacity - self.count - byteCount >= 0,
            "Insufficient space for byte copying, must have reallocated!"
        )

        let lowerOffset = self.count
        self._withVeryUnsafeMutableBytes { bytesPtr in
            let innerPtrSlice = UnsafeMutableRawBufferPointer(rebasing: bytesPtr[lowerOffset...])
            innerPtrSlice.copyBytes(from: bytes)
        }
        self.count += byteCount
    }

    /// Appends the bytes of a slice of another backing buffer to this storage, crashing if there
    /// is not enough room.
    @usableFromInline
    /* private but inlinable */ func _appendBytes(
        _ backing: SecureBytes.Backing,
        inRange range: Range<Int>
    ) {
        precondition(range.lowerBound >= 0)
        precondition(range.upperBound <= backing.capacity)
        precondition(
            self.capacity - self.count - range.count >= 0,
            "Insufficient space for byte copying, must have reallocated!"
        )

        backing.withUnsafeBytes { backingPtr in
            let ptrSlice = UnsafeRawBufferPointer(rebasing: backingPtr[range])

            let lowerOffset = self.count
            self._withVeryUnsafeMutableBytes { bytesPtr in
                let innerPtrSlice = UnsafeMutableRawBufferPointer(
                    rebasing: bytesPtr[lowerOffset...]
                )
                innerPtrSlice.copyMemory(from: ptrSlice)
            }
            self.count += ptrSlice.count
        }
    }

    /// Moves the range of bytes identified by the slice by the delta, crashing if the move would
    /// place the bytes out of the storage. Note that this does not update the count: external code
    /// must ensure that that happens.
    @usableFromInline
    /* private but usableFromInline */ func _moveBytes(range: Range<Int>, by delta: Int) {
        // We have to check that the range is within the delta, as is the new location.
        precondition(range.lowerBound >= 0)
        precondition(range.upperBound <= self.capacity)

        let shiftedRange = (range.lowerBound + delta)..<(range.upperBound + delta)
        precondition(shiftedRange.lowerBound > 0)
        precondition(shiftedRange.upperBound <= self.capacity)

        self._withVeryUnsafeMutableBytes { backingPtr in
            let source = UnsafeRawBufferPointer(rebasing: backingPtr[range])
            let dest = UnsafeMutableRawBufferPointer(rebasing: backingPtr[shiftedRange])
            dest.copyMemory(from: source)  // copy memory uses memmove under the hood.
        }
    }

    // Copies some bytes into the buffer at the appropriate place. Does not update count: external code must do so.
    @inlinable
    /* private but inlinable */ func _copyBytes<C: Collection>(_ bytes: C, at offset: Int)
    where C.Element == UInt8 {
        precondition(offset >= 0)
        precondition(offset + bytes.count <= self.capacity)

        let byteRange = offset..<(offset + bytes.count)

        self._withVeryUnsafeMutableBytes { backingPtr in
            let dest = UnsafeMutableRawBufferPointer(rebasing: backingPtr[byteRange])
            dest.copyBytes(from: bytes)
        }
    }
}

extension SecureBytes.Backing: ContiguousBytes {

    @usableFromInline
    func withUnsafeBytes<T>(_ body: (UnsafeRawBufferPointer) throws -> T) rethrows -> T {
        let count = self.count

        return try self.withUnsafeMutablePointerToElements { elementsPtr in
            return try body(UnsafeRawBufferPointer(start: elementsPtr, count: count))
        }
    }

    @usableFromInline
    func withUnsafeMutableBytes<T>(_ body: (UnsafeMutableRawBufferPointer) throws -> T) rethrows
        -> T
    {
        let count = self.count

        return try self.withUnsafeMutablePointerToElements { elementsPtr in
            return try body(UnsafeMutableRawBufferPointer(start: elementsPtr, count: count))
        }
    }

    /// Very unsafe in the sense that this points to uninitialized memory. Used only for implementations within this file.
    @inlinable
    /* private but inlinable */ func _withVeryUnsafeMutableBytes<T>(
        _ body: (UnsafeMutableRawBufferPointer) throws -> T
    ) rethrows -> T {
        let capacity = self.capacity

        return try self.withUnsafeMutablePointerToElements { elementsPtr in
            return try body(UnsafeMutableRawBufferPointer(start: elementsPtr, count: capacity))
        }
    }
}

extension UnsafeMutableRawBufferPointer {
    func initializeWithRandomBytes(count: Int) {
        guard count > 0 else {
            return
        }

        precondition(count <= self.count)
        var rng = SystemRandomNumberGenerator()

        // We store bytes 64-bits at a time until we can't anymore.
        var targetPtr = self
        while targetPtr.count > 8 {
            targetPtr.storeBytes(of: rng.next(), as: UInt64.self)
            targetPtr = UnsafeMutableRawBufferPointer(rebasing: targetPtr[8...])
        }

        // Now we're down to having to store things an integer at a time. We do this by shifting and
        // masking.
        var remainingWord: UInt64 = rng.next()
        while targetPtr.count > 0 {
            targetPtr.storeBytes(of: UInt8(remainingWord & 0xFF), as: UInt8.self)
            remainingWord >>= 8
            targetPtr = UnsafeMutableRawBufferPointer(rebasing: targetPtr[1...])
        }
    }
}

/// This function performs a safe comparison between two buffers of bytes. It exists as a temporary shim until we refactor
/// some of the usage sites to pass better data structures to us.
@inlinable
internal func safeCompare<LHS: ContiguousBytes, RHS: ContiguousBytes>(_ lhs: LHS, _ rhs: RHS)
    -> Bool
{
    return lhs.withUnsafeBytes { lhsPtr in
        rhs.withUnsafeBytes { rhsPtr in
            constantTimeCompare(lhsPtr, rhsPtr)
        }
    }
}

/// A straightforward constant-time comparison function for any two collections of bytes.
@inlinable
internal func constantTimeCompare<LHS: Collection, RHS: Collection>(_ lhs: LHS, _ rhs: RHS) -> Bool
where LHS.Element == UInt8, RHS.Element == UInt8 {
    guard lhs.count == rhs.count else {
        return false
    }

    return zip(lhs, rhs).reduce(into: 0) { $0 |= $1.0 ^ $1.1 } == 0
}

extension UInt32 {
    /// Returns the next power of two unless that would overflow, in which case UInt32.max (on 64-bit systems) or
    /// Int32.max (on 32-bit systems) is returned. The returned value is always safe to be cast to Int and passed
    /// to malloc on all platforms.
    func nextPowerOf2ClampedToMax() -> UInt32 {
        guard self > 0 else {
            return 1
        }

        var n = self

        #if arch(arm) || arch(i386)
        // on 32-bit platforms we can't make use of a whole UInt32.max (as it doesn't fit in an Int)
        let max = UInt32(Int.max)
        #else
        // on 64-bit platforms we're good
        let max = UInt32.max
        #endif

        n -= 1
        n |= n >> 1
        n |= n >> 2
        n |= n >> 4
        n |= n >> 8
        n |= n >> 16
        if n != max {
            n += 1
        }

        return n
    }
}

extension Data {
    /// A custom initializer for Data that attempts to share the same storage as the current SecureBytes instance.
    /// This is our best-effort attempt to expose the data in an auto-zeroing fashion. Any mutating function called on
    /// the constructed `Data` object will cause the bytes to be copied out: we can't avoid that.
    public init(_ secureBytes: SecureBytes) {
        // We need to escape into unmanaged land here in order to keep the backing storage alive.
        let unmanagedBacking = Unmanaged.passRetained(secureBytes.backing)

        // We can now exfiltrate the storage pointer: this particular layout will be locked forever. Please never do this
        // yourself unless you're really sure!
        self = secureBytes.withUnsafeBytes {
            // We make a mutable copy of this pointer here because we know Data won't write through it.
            return Data(
                bytesNoCopy: UnsafeMutableRawPointer(mutating: $0.baseAddress!),
                count: $0.count,
                deallocator: .custom { (_: UnsafeMutableRawPointer, _: Int) in
                    unmanagedBacking.release()
                }
            )
        }
    }

    /// A custom initializer for Data that attempts to share the same storage as the current SecureBytes instance.
    /// This is our best-effort attempt to expose the data in an auto-zeroing fashion. Any mutating function called on the
    /// constructed `Data` object will cause the bytes to be copied out: we can't avoid that.
    public init(_ secureByteSlice: Slice<SecureBytes>) {
        // We have a trick here: we use the same function as the one above, but we use the indices of the slice to bind
        // the scope of the pointer we pass to Data.
        let base = secureByteSlice.base
        let baseOffset = secureByteSlice.startIndex.offset
        let endOffset = secureByteSlice.endIndex.offset

        // We need to escape into unmanaged land here in order to keep the backing storage alive.
        let unmanagedBacking = Unmanaged.passRetained(base.backing)

        // We can now exfiltrate the storage pointer: this particular layout will be locked forever. Please never do this
        // yourself unless you're really sure!
        self = base.withUnsafeBytes {
            // Slice the base pointer down to just the range we want.
            let slicedPointer = UnsafeRawBufferPointer(rebasing: $0[baseOffset..<endOffset])

            // We make a mutable copy of this pointer here because we know Data won't write through it.
            return Data(
                bytesNoCopy: UnsafeMutableRawPointer(mutating: slicedPointer.baseAddress!),
                count: slicedPointer.count,
                deallocator: .custom { (_: UnsafeMutableRawPointer, _: Int) in
                    unmanagedBacking.release()
                }
            )
        }
    }
}
