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

/// `ProtocolVersion` defines VMESS protocol version.
public struct ProtocolVersion: Codable, Equatable, RawRepresentable, Sendable {

  public var rawValue: UInt8

  public init(rawValue: UInt8) {
    self.rawValue = rawValue
  }
}

extension ProtocolVersion {

  /// VMESS protocol version 1.
  public static let v1 = ProtocolVersion.init(rawValue: 0x01)
}

/// `Algorithm` defines current VMESS supported data security algorithm.
public enum Algorithm: UInt8, Codable, Equatable, Sendable {

  /// AES-128-CFB
  case aes128cfb = 1

  /// AES-128-GCM
  case aes128gcm = 3

  /// ChaCha20-Poly1305
  case chacha20poly1305 = 4

  case none = 5

  case zero = 6

  var shouldEnablePadding: Bool {
    self == .aes128gcm || self == .chacha20poly1305
  }

  // For `AES-GCM` and `ChaChaPoly` overhead is tag byte count.
  var overhead: Int {
    switch self {
    case .aes128gcm, .chacha20poly1305:
      return 16
    default:
      return 0
    }
  }
}

/// `Command` object defines VMESS command.
public struct Command: Codable, Equatable, RawRepresentable, Sendable {

  public typealias RawValue = UInt8

  public let rawValue: UInt8

  public init(rawValue: UInt8) {
    self.rawValue = rawValue
  }
}

extension Command {

  /// The TCP command.
  public static let tcp = Command.init(rawValue: 0x01)

  /// The DUP command.
  public static let udp = Command.init(rawValue: 0x02)

  /// The MUX command.
  public static let mux = Command.init(rawValue: 0x03)
}

/// A `StreamOptions` that contains VMESS stream setting options.
public struct StreamOptions: Codable, Equatable, OptionSet, Sendable {

  public typealias RawValue = UInt8

  public var rawValue: UInt8

  var shouldPadding: Bool {
    contains(.masking) && contains(.padding)
  }

  public init(rawValue: RawValue) {
    self.rawValue = rawValue
  }
}

extension StreamOptions {

  /// Standard data stream option
  public static let chunked = StreamOptions.init(rawValue: 1 << 0)

  @available(*, deprecated, message: "This options is deprecated from V2Ray 2.23+.")
  public static let connectionReuse = StreamOptions.init(rawValue: 1 << 1)

  /// Turn on stream masking.
  ///
  /// This options is valid only when `.chunked` is turned on.
  public static let masking = StreamOptions.init(rawValue: 1 << 2)

  /// Turn on stream padding.
  ///
  /// This options is valid only when `.chunked` is turned on.
  public static let padding = StreamOptions.init(rawValue: 0x08)

  /// Turn on packet length authentication.
  public static let authenticatedLength = StreamOptions.init(rawValue: 0x10)
}
