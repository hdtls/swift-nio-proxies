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

import _NELinux

#if os(iOS) || os(macOS) || os(tvOS) || os(watchOS)
import Foundation
#else
@preconcurrency import Foundation
#endif

/// `Version` defines VMESS protocol version.
public struct VMESSVersion: Hashable, RawRepresentable, Sendable {

  public var rawValue: UInt8

  public init(rawValue: UInt8) {
    self.rawValue = rawValue
  }
}

extension VMESSVersion {

  /// VMESS protocol version 1.
  public static let v1 = VMESSVersion.init(rawValue: 0x01)
}

/// `ContentSecurity` defines current VMESS supported data security algorithm.
public struct ContentSecurity: RawRepresentable, Hashable, Sendable {

  public var rawValue: UInt8

  public init(rawValue: UInt8) {
    self.rawValue = rawValue
  }

  /// AES-128-CFB
  public static let aes128Cfb = ContentSecurity(rawValue: 0x01)

  public static let auto = ContentSecurity(rawValue: 0x02)

  /// AES-128-GCM
  public static let aes128Gcm = ContentSecurity(rawValue: 0x03)

  /// ChaCha20-Poly1305
  public static let chaCha20Poly1305 = ContentSecurity(rawValue: 0x04)

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

public protocol ResponseInstruction: Sendable {}

public struct DynamicPortInstruction: ResponseInstruction, Hashable {

  public var address: String?

  public var port: Int

  public var uid: UUID

  public var level: UInt32

  public var numberOfAlterIDs: UInt16

  public var effectiveTime: UInt8

  public init(
    address: String? = nil,
    port: Int,
    uid: UUID,
    level: UInt32,
    numberOfAlterIDs: UInt16,
    effectiveTime: UInt8
  ) {
    self.address = address
    self.port = port
    self.uid = uid
    self.level = level
    self.numberOfAlterIDs = numberOfAlterIDs
    self.effectiveTime = effectiveTime
  }
}

public struct InstructionCode: Hashable, RawRepresentable, Sendable {

  public typealias RawValue = UInt8

  public let rawValue: UInt8

  public init(rawValue: UInt8) {
    self.rawValue = rawValue
  }
}

/// A representation of the response header  frame of a VMESS response.
public struct VMESSResponseHead: Hashable {

  final private class _Storage {
    /// Authentication code.
    fileprivate var authenticationCode: UInt8

    /// Stream options.
    fileprivate var options: StreamOptions

    /// Instruction code.
    fileprivate var instructionCode: InstructionCode

    /// Instruction.
    fileprivate var instruction: ResponseInstruction?

    fileprivate init(
      authenticationCode: UInt8,
      options: StreamOptions,
      instructionCode: InstructionCode,
      instruction: ResponseInstruction?
    ) {
      self.authenticationCode = authenticationCode
      self.options = options
      self.instructionCode = instructionCode
      self.instruction = instruction
    }

    fileprivate func copy() -> _Storage {
      return .init(
        authenticationCode: authenticationCode,
        options: options,
        instructionCode: instructionCode,
        instruction: instruction
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

  /// Instruction code.
  public var instructionCode: InstructionCode {
    get {
      return self._storage.instructionCode
    }
    set {
      self.copyStorageIfNotUniquelyReferenced()
      self._storage.instructionCode = newValue
    }
  }

  /// Instruction.
  public var instruction: ResponseInstruction? {
    get {
      return self._storage.instruction
    }
    set {
      self.copyStorageIfNotUniquelyReferenced()
      self._storage.instruction = newValue
    }
  }

  public init(
    authenticationCode: UInt8,
    options: StreamOptions,
    instructionCode: InstructionCode,
    instruction: ResponseInstruction?
  ) {
    self._storage = .init(
      authenticationCode: authenticationCode,
      options: options,
      instructionCode: instructionCode,
      instruction: instruction
    )
  }

  public static func == (lhs: VMESSResponseHead, rhs: VMESSResponseHead) -> Bool {
    lhs.authenticationCode == rhs.authenticationCode && lhs.options == rhs.options
      && lhs.instructionCode == rhs.instructionCode
  }

  public func hash(into hasher: inout Hasher) {
    hasher.combine(authenticationCode)
    hasher.combine(options)
    hasher.combine(instructionCode)
  }

  private mutating func copyStorageIfNotUniquelyReferenced() {
    if !isKnownUniquelyReferenced(&self._storage) {
      self._storage = self._storage.copy()
    }
  }
}

extension VMESSResponseHead: @unchecked Sendable {}

/// A representation of the request header  frame of a VMESS request.
public struct VMESSRequestHead: Hashable {

  final private class _Storage {

    fileprivate var version: VMESSVersion = .v1

    fileprivate var user: UUID

    fileprivate var authenticationCode: UInt8

    fileprivate var contentSecurity: ContentSecurity

    fileprivate var options: StreamOptions

    fileprivate var commandCode: CommandCode

    fileprivate var address: NWEndpoint

    fileprivate init(
      version: VMESSVersion,
      user: UUID,
      authenticationCode: UInt8,
      contentSecurity: ContentSecurity,
      options: StreamOptions,
      commandCode: CommandCode,
      address: NWEndpoint
    ) {
      self.version = version
      self.user = user
      self.authenticationCode = authenticationCode
      self.contentSecurity = contentSecurity
      self.options = options
      self.commandCode = commandCode
      self.address = address
    }

    fileprivate func copy() -> _Storage {
      .init(
        version: version,
        user: user,
        authenticationCode: authenticationCode,
        contentSecurity: contentSecurity,
        options: options,
        commandCode: commandCode,
        address: address
      )
    }
  }

  private var _storage: _Storage

  public var version: VMESSVersion {
    get {
      return self._storage.version
    }
    set {
      self.copyStorageIfNotUniquelyReferenced()
      self._storage.version = newValue
    }
  }

  public var user: UUID {
    get {
      return self._storage.user
    }
    set {
      self.copyStorageIfNotUniquelyReferenced()
      self._storage.user = newValue
    }
  }

  public var authenticationCode: UInt8 {
    get {
      return self._storage.authenticationCode
    }
    set {
      self.copyStorageIfNotUniquelyReferenced()
      self._storage.authenticationCode = newValue
    }
  }

  public var contentSecurity: ContentSecurity {
    get {
      return self._storage.contentSecurity
    }
    set {
      self.copyStorageIfNotUniquelyReferenced()
      self._storage.contentSecurity = newValue
    }
  }

  public var options: StreamOptions {
    get {
      return self._storage.options
    }
    set {
      self.copyStorageIfNotUniquelyReferenced()
      self._storage.options = newValue
    }
  }

  public var commandCode: CommandCode {
    get {
      return self._storage.commandCode
    }
    set {
      self.copyStorageIfNotUniquelyReferenced()
      self._storage.commandCode = newValue
    }
  }

  public var address: NWEndpoint {
    get {
      return self._storage.address
    }
    set {
      self.copyStorageIfNotUniquelyReferenced()
      self._storage.address = newValue
    }
  }

  public init(
    version: VMESSVersion = .v1,
    user: UUID,
    authenticationCode: UInt8,
    algorithm: ContentSecurity,
    options: StreamOptions,
    commandCode: CommandCode,
    address: NWEndpoint
  ) {
    self._storage = .init(
      version: version,
      user: user,
      authenticationCode: authenticationCode,
      contentSecurity: algorithm,
      options: options,
      commandCode: commandCode,
      address: address
    )
  }

  public static func == (lhs: VMESSRequestHead, rhs: VMESSRequestHead) -> Bool {
    lhs.version == rhs.version
      && lhs.user == rhs.user
      && lhs.authenticationCode == rhs.authenticationCode
      && lhs.contentSecurity == rhs.contentSecurity
      && lhs.options == rhs.options
      && lhs.commandCode == rhs.commandCode
      && lhs.address == rhs.address
  }

  public func hash(into hasher: inout Hasher) {
    hasher.combine(version)
    hasher.combine(user)
    hasher.combine(authenticationCode)
    hasher.combine(contentSecurity)
    hasher.combine(options)
    hasher.combine(commandCode)
    hasher.combine(address)
  }

  private mutating func copyStorageIfNotUniquelyReferenced() {
    if !isKnownUniquelyReferenced(&self._storage) {
      self._storage = self._storage.copy()
    }
  }
}

extension VMESSRequestHead: @unchecked Sendable {}

/// The parts of a complete VMESS message, either request or response.
public enum VMESSPart<HeadT: Equatable, BodyT: Equatable> {
  case head(HeadT)
  case body(BodyT)
  case end
}

extension VMESSPart: Sendable where HeadT: Sendable, BodyT: Sendable {}

extension VMESSPart: Equatable {}
