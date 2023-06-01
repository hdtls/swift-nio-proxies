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
import NEMisc

/// `ProtocolVersion` defines VMESS protocol version.
public struct ProtocolVersion: Hashable, RawRepresentable, Sendable {

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
public enum Algorithm: UInt8, Hashable, Sendable {

  /// AES-128-CFB
  case aes128cfb = 1

  /// AES-128-GCM
  case aes128Gcm = 3

  /// ChaCha20-Poly1305
  case chaCha20Poly1305 = 4

  case none = 5

  case zero = 6

  var shouldEnablePadding: Bool {
    self == .aes128Gcm || self == .chaCha20Poly1305
  }

  // For `AES-GCM` and `ChaChaPoly` overhead is tag byte count.
  var overhead: Int {
    switch self {
    case .aes128Gcm, .chaCha20Poly1305:
      return 16
    default:
      return 0
    }
  }
}

/// `Command` object defines VMESS command.
public struct Command: Hashable, RawRepresentable, Sendable {

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
public struct StreamOptions: Hashable, OptionSet, Sendable {

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

public protocol ResponseCommand: Sendable {}

public struct SwitchAccountCommand: ResponseCommand, Hashable {

  var id: UUID

  var level: UInt32

  var countOfAlterIDs: UInt16

  var address: NetAddress?

  var validMin: UInt8
}

/// A representation of the response header  frame of a VMESS response.
public struct VMESSResponseHead: Hashable {

  private final class _Storage {
    /// Authentication code.
    var authenticationCode: UInt8

    /// Stream options.
    var options: StreamOptions

    /// Command code.
    var commandCode: UInt8

    /// Command.
    var command: ResponseCommand?

    init(
      authenticationCode: UInt8,
      options: StreamOptions,
      commandCode: UInt8,
      command: ResponseCommand?
    ) {
      self.authenticationCode = authenticationCode
      self.options = options
      self.commandCode = commandCode
      self.command = command
    }

    func copy() -> _Storage {
      return .init(
        authenticationCode: authenticationCode,
        options: options,
        commandCode: commandCode,
        command: command
      )
    }
  }

  private var _storage: _Storage

  /// Authentication code.
  public var authenticationCode: UInt8 {
    get {
      return self._storage.authenticationCode
    }
    set {
      self.copyStorageIfNotUniquelyReferenced()
      self._storage.authenticationCode = newValue
    }
  }

  /// Stream options.
  public var options: StreamOptions {
    get {
      return self._storage.options
    }
    set {
      self.copyStorageIfNotUniquelyReferenced()
      self._storage.options = newValue
    }
  }

  /// Command code.
  public var commandCode: UInt8 {
    get {
      return self._storage.commandCode
    }
    set {
      self.copyStorageIfNotUniquelyReferenced()
      self._storage.commandCode = newValue
    }
  }

  /// Command.
  public var command: ResponseCommand? {
    get {
      return self._storage.command
    }
    set {
      self.copyStorageIfNotUniquelyReferenced()
      self._storage.command = newValue
    }
  }

  public init(
    authenticationCode: UInt8,
    options: StreamOptions,
    commandCode: UInt8,
    command: ResponseCommand?
  ) {
    self._storage = .init(
      authenticationCode: authenticationCode,
      options: options,
      commandCode: commandCode,
      command: command
    )
  }

  public static func == (lhs: VMESSResponseHead, rhs: VMESSResponseHead) -> Bool {
    lhs.authenticationCode == rhs.authenticationCode && lhs.options == rhs.options
      && lhs.commandCode == rhs.commandCode
  }

  public func hash(into hasher: inout Hasher) {
    hasher.combine(authenticationCode)
    hasher.combine(options)
    hasher.combine(commandCode)
  }

  private mutating func copyStorageIfNotUniquelyReferenced() {
    if !isKnownUniquelyReferenced(&self._storage) {
      self._storage = self._storage.copy()
    }
  }
}

extension VMESSResponseHead: @unchecked Sendable {}

/// The parts of a complete VMESS message, either request or response.
public enum VMESSPart<HeadT: Equatable, BodyT: Equatable> {
  case head(HeadT)
  case body(BodyT)
  case end
}

extension VMESSPart: Sendable where HeadT: Sendable, BodyT: Sendable {}

extension VMESSPart: Equatable {}
