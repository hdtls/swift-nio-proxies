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

import NEMisc

#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
import Foundation
#else
@preconcurrency import Foundation
#endif

/// `Version` defines VMESS protocol version.
public struct Version: Hashable, RawRepresentable, Sendable {

  public var rawValue: UInt8

  public init(rawValue: UInt8) {
    self.rawValue = rawValue
  }
}

extension Version {

  /// VMESS protocol version 1.
  public static let v1 = Version.init(rawValue: 0x01)
}

/// `Algorithm` defines current VMESS supported data security algorithm.
public struct ContentSecurity: RawRepresentable, Hashable, Sendable {

  public var rawValue: UInt8

  public init(rawValue: UInt8) {
    self.rawValue = rawValue
  }

  public static let unknown = ContentSecurity(rawValue: 0x00)

  /// AES-CFB-128
  public static let encryptByAESCFB128 = ContentSecurity(rawValue: 0x01)

  public static let auto = ContentSecurity(rawValue: 0x02)

  /// AES-128-GCM
  public static let encryptByAES128GCM = ContentSecurity(rawValue: 0x03)

  /// ChaCha20-Poly1305
  public static let encryptByChaCha20Poly1305 = ContentSecurity(rawValue: 0x04)

  public static let none = ContentSecurity(rawValue: 0x05)

  public static let zero = ContentSecurity(rawValue: 0x06)
}

/// `CommandCode` object defines VMESS command.
public struct CommandCode: Hashable, RawRepresentable, Sendable {

  public typealias RawValue = UInt8

  public let rawValue: UInt8

  public init(rawValue: UInt8) {
    self.rawValue = rawValue
  }
}

extension CommandCode {

  /// The TCP command.
  public static let tcp = CommandCode.init(rawValue: 0x01)

  /// The DUP command.
  public static let udp = CommandCode.init(rawValue: 0x02)

  /// The MUX command.
  public static let mux = CommandCode.init(rawValue: 0x03)
}

/// A `StreamOptions` that contains VMESS stream setting options.
public struct StreamOptions: Hashable, OptionSet, Sendable {

  public typealias RawValue = UInt8

  public var rawValue: UInt8

  public init(rawValue: RawValue) {
    self.rawValue = rawValue
  }
}

extension StreamOptions {

  /// Standard data stream option
  public static let chunkStream = StreamOptions.init(rawValue: 1 << 0)

  @available(*, deprecated, message: "This options is deprecated from V2Ray 2.23+.")
  public static let connectionReuse = StreamOptions.init(rawValue: 1 << 1)

  /// Turn on stream masking.
  public static let chunkMasking = StreamOptions.init(rawValue: 1 << 2)

  /// Turn on stream padding.
  public static let globalPadding = StreamOptions.init(rawValue: 0x08)

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

  final private class _Storage {
    /// Authentication code.
    var authenticationCode: UInt8

    /// Stream options.
    var options: StreamOptions

    /// Command code.
    var commandCode: CommandCode

    /// Command.
    var command: ResponseCommand?

    init(
      authenticationCode: UInt8,
      options: StreamOptions,
      commandCode: CommandCode,
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
  public var commandCode: CommandCode {
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
    commandCode: CommandCode,
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

/// A representation of the request header  frame of a VMESS request.
public struct VMESSRequestHead: Hashable, Sendable {

  public var version: Version = .v1

  public var user: UUID

  public var authenticationCode: UInt8

  public var contentSecurity: ContentSecurity

  public var options: StreamOptions

  public var commandCode: CommandCode

  public var address: NetAddress

  public init(
    version: Version = .v1,
    user: UUID,
    authenticationCode: UInt8,
    algorithm: ContentSecurity,
    options: StreamOptions,
    commandCode: CommandCode,
    address: NetAddress
  ) {
    self.version = version
    self.user = user
    self.authenticationCode = authenticationCode
    self.contentSecurity = algorithm
    self.options = options
    self.commandCode = commandCode
    self.address = address
  }
}

/// The parts of a complete VMESS message, either request or response.
public enum VMESSPart<HeadT: Equatable, BodyT: Equatable> {
  case head(HeadT)
  case body(BodyT)
  case end
}

extension VMESSPart: Sendable where HeadT: Sendable, BodyT: Sendable {}

extension VMESSPart: Equatable {}
