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

import Foundation

/// `Configuration` object defines VMESS request infomation.
public struct Configuration: Sendable {

    /// The VMESS protocol version.
    public let version: ProtocolVersion = .v1

    /// ID
    public let id: UUID

    /// The encryption method.
    public let algorithm: Algorithm

    /// Request command.
    public let command: Command

    /// Current request stream options.
    ///
    /// This value is will updated by algorithm.
    public let options: StreamOptions

    /// Initialize an instance of `Profile` with specified id, algorithm, command, and options.
    /// - Parameters:
    ///   - id: The id identifier current user.
    ///   - algorithm: The algorithm to encryption data.
    ///   - command: The VMESS command object.
    ///   - options: The stream options.
    public init(id: UUID, algorithm: Algorithm, command: Command, options: StreamOptions) {
        self.id = id
        self.command = command
        self.algorithm = algorithm == .zero ? .none : algorithm

        var options: StreamOptions = .chunked
        if algorithm == .aes128gcm || algorithm == .chacha20poly1305 || algorithm == .none {
            options.insert(.masking)
        }

        if algorithm.shouldEnablePadding && options.contains(.masking) {
            options.insert(.padding)
        }

        if algorithm == .zero {
            options.remove(.chunked)
            options.remove(.masking)
        }
        self.options = options
    }
}
