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

/// Cryptor (Encryptor or Decryptor)
public protocol Cryptor {
    /// Seek to position in file, if block mode allows random access.
    ///
    /// - parameter to: new value of counter
    //    mutating func seek(to: Int) throws

    var iv: [UInt8] { get }
    var key: [UInt8] { get }
    var algorithm: Algorithm { get }
}

/// Worker cryptor/decryptor of `Updatable` types
public protocol Cryptors: AnyObject {

    /// Cryptor suitable for encryption
    func makeEncryptor() throws -> Cryptor & Updatable

    /// Cryptor suitable for decryption
    func makeDecryptor() throws -> Cryptor & Updatable
}
