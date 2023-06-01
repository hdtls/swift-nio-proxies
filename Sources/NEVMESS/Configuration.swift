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

#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
import Foundation
#else
@preconcurrency import Foundation
#endif

/// `Configuration` object defines VMESS request infomation.
public struct Configuration: Sendable {

  /// The VMESS protocol version.
  public let version: Version = .v1

  /// ID
  public let id: UUID

  /// The encryption method.
  public let contentSecurity: ContentSecurity

  /// Request command.
  public let command: CommandCode

  /// Current request stream options.
  ///
  /// This value is will updated by algorithm.
  public let options: StreamOptions

  /// Initialize an instance of `Profile` with specified id, algorithm, command, and options.
  /// - Parameters:
  ///   - id: The id identifier current user.
  ///   - contentSecurity: The algorithm to encryption data.
  ///   - command: The VMESS command object.
  ///   - options: The stream options.
  public init(
    id: UUID,
    contentSecurity: ContentSecurity,
    command: CommandCode,
    options: StreamOptions
  ) {
    self.id = id
    self.command = command
    self.contentSecurity = contentSecurity == .zero ? .none : contentSecurity

    var options: StreamOptions = .chunked
    if contentSecurity == .encryptByAES128GCM || contentSecurity == .encryptByChaCha20Poly1305
      || contentSecurity == .none
    {
      options.insert(.masking)
    }

    if (contentSecurity == .encryptByAES128GCM || contentSecurity == .encryptByChaCha20Poly1305)
      && options.contains(.masking)
    {
      options.insert(.padding)
    }

    if contentSecurity == .zero {
      options.remove(.chunked)
      options.remove(.masking)
    }
    self.options = options
  }
}
