//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright © 2019 Netbot Ltd. and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

/// A type that supports incremental updates. For example Digest or Cipher may be updatable
/// and calculate result incerementally.
public protocol Updatable {
    /// Update given bytes in chunks.
    ///
    /// - parameter bytes: Bytes to process.
    /// - parameter isLast: Indicate if given chunk is the last one. No more updates after this call.
    /// - returns: Processed partial result data or empty array.
    func update(_ bytes: ArraySlice<UInt8>, isLast: Bool) throws -> Array<UInt8>

    /// Update given bytes in chunks.
    ///
    /// - Parameters:
    ///   - bytes: Bytes to process.
    ///   - isLast: Indicate if given chunk is the last one. No more updates after this call.
    ///   - output: Resulting bytes callback.
    /// - Returns: Processed partial result data or empty array.
    func update(_ bytes: ArraySlice<UInt8>, isLast: Bool, output: (_ bytes: Array<UInt8>) -> Void) throws
}

extension Updatable {
    public func update(_ bytes: ArraySlice<UInt8>, isLast: Bool = false, output: (_ bytes: Array<UInt8>) -> Void) throws {
        let processed = try update(bytes, isLast: isLast)
        if !processed.isEmpty {
            output(processed)
        }
    }

    public func update(_ bytes: ArraySlice<UInt8>, isLast: Bool = false) throws -> Array<UInt8> {
        return try update(bytes, isLast: isLast)
    }

    public func update(_ bytes: Array<UInt8>, isLast: Bool = false) throws -> Array<UInt8> {
        return try update(bytes.slice, isLast: isLast)
    }

    public func update(_ bytes: Array<UInt8>, isLast: Bool = false, output: (_ bytes: Array<UInt8>) -> Void) throws {
        return try update(bytes.slice, isLast: isLast, output: output)
    }

    /// Finish updates. This may apply padding.
    /// - parameter bytes: Bytes to process
    /// - returns: Processed data.
    public func finish(_ bytes: ArraySlice<UInt8>) throws -> Array<UInt8> {
        return try update(bytes, isLast: true)
    }

    public func finish(_ bytes: Array<UInt8>) throws -> Array<UInt8> {
        return try finish(bytes.slice)
    }


    /// Finish updates. May add padding.
    ///
    /// - Returns: Processed data
    /// - Throws: Error
    public func finish() throws -> Array<UInt8> {
        return try update([], isLast: true)
    }

    /// Finish updates. This may apply padding.
    /// - parameter bytes: Bytes to process
    /// - parameter output: Resulting data
    /// - returns: Processed data.
    public func finish(_ bytes: ArraySlice<UInt8>, output: (_ bytes: Array<UInt8>) -> Void) throws {
        let processed = try update(bytes, isLast: true)
        if !processed.isEmpty {
            output(processed)
        }
    }

    public func finish(_ bytes: Array<UInt8>, output: (_ bytes: Array<UInt8>) -> Void) throws {
        return try finish(bytes.slice, output: output)
    }

    /// Finish updates. May add padding.
    ///
    /// - Parameter output: Processed data
    /// - Throws: Error
    public func finish(output: (Array<UInt8>) -> Void) throws {
        try finish([], output: output)
    }
}
