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

/// Worker cryptor/decryptor of `Updatable` types
public protocol Cryptors: class {

    /// Cryptor suitable for encryption
    func makeEncryptor() throws -> Cryptor & Updatable

    /// Cryptor suitable for decryption
    func makeDecryptor() throws -> Cryptor & Updatable
}
