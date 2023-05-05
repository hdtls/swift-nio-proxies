//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2021 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation
@_exported import NIOCore

/// Represent a socket address or domain port to which we may want to connect or bind.
public enum NetAddress: Equatable, Hashable, Sendable {
  case domainPort(host: String, port: Int)
  case socketAddress(SocketAddress)

  public var host: String? {
    switch self {
    case .domainPort(let host, _):
      return host
    case .socketAddress(let socketAddress):
      return socketAddress.ipAddress
    }
  }

  public var port: Int? {
    switch self {
    case .domainPort(_, let port):
      return port
    case .socketAddress(let socketAddress):
      return socketAddress.port
    }
  }
}

/// SOCKS address identifier defined in RFC 1928.
private enum AddressFlag: UInt8 {
  // IPv4 address identifier
  case v4 = 0x01

  // Domain address identifier
  case domain = 0x03

  // IPv6 address identifier
  case v6 = 0x04
}

extension ByteBuffer {

  /// ByteBuffer parse helper.
  ///
  /// This function gives the user a chance to parse from a byte buffer, once the parse success then the buffer will read parsed bytes
  /// and return the parsed object, else byte buffer will fall back to the original state nil will be returned.
  ///
  /// - Parameter closure: The parse operation closure.
  /// - Returns: The parsed object if success or nil.
  public mutating func parseUnwinding<T>(_ closure: (inout ByteBuffer) throws -> T?) rethrows -> T?
  {
    let save = self
    do {
      guard let value = try closure(&self) else {
        self = save
        return nil
      }
      return value
    } catch {
      self = save
      throw error
    }
  }
}

extension ByteBuffer {

  /// Read `NetAddress` from buffer.
  ///
  /// This method is used to parse address that encoded as SOCKS address defined in RFC 1928.
  ///
  /// - Throws: May throw  `SocketAddressError.unsupported` if address type is illegal,
  ///     or `SocketAddressError.FailedToParseIPByteBuffer(address:)` if failed to parse ipaddress.
  /// - Returns: If success return `NetAddress` else return nil for need more bytes.
  public mutating func readAddress() throws -> NetAddress? {
    try parseUnwinding { buffer in
      guard let rawValue = buffer.readInteger(as: UInt8.self) else {
        return nil
      }

      guard let type = AddressFlag(rawValue: rawValue) else {
        throw SocketAddressError.unsupported
      }

      switch type {
      case .domain:
        // Unlike IPv4 and IPv6 address domain name have a variable length
        guard let length = buffer.readInteger(as: UInt8.self),
          let host = buffer.readString(length: Int(length)),
          let port = buffer.readInteger(as: UInt16.self)
        else {
          return nil
        }
        return .domainPort(host: host, port: Int(port))
      case .v4, .v6:
        guard let packedIPAddress = buffer.readSlice(length: type == .v4 ? 4 : 16),
          let port = buffer.readInteger(as: UInt16.self)
        else {
          return nil
        }
        return .socketAddress(try .init(packedIPAddress: packedIPAddress, port: Int(port)))
      }
    }
  }

  /// Write `NetAddress` to `ByteBuffer`.
  /// - Parameter address: The address waiting to write.
  /// - Returns: Byte count.
  @discardableResult
  public mutating func writeAddress(_ address: NetAddress) -> Int {
    switch address {
    case .socketAddress(.v4(let address)):
      return writeInteger(AddressFlag.v4.rawValue)
        + withUnsafeBytes(of: address.address.sin_addr) { ptr in
          writeBytes(ptr)
        }
        + writeInteger(address.address.sin_port.bigEndian)
    case .socketAddress(.v6(let address)):
      return writeInteger(AddressFlag.v6.rawValue)
        + withUnsafeBytes(of: address.address.sin6_addr) { ptr in
          writeBytes(ptr)
        }
        + writeInteger(address.address.sin6_port.bigEndian)
    case .socketAddress(.unixDomainSocket):
      // enforced in the channel initalisers.
      fatalError("UNIX domain sockets are not supported")
    case .domainPort(let domain, let port):
      return writeInteger(AddressFlag.domain.rawValue)
        + writeInteger(UInt8(domain.utf8.count))
        + writeString(domain)
        + writeInteger(UInt16(port))
    }
  }
}

extension Data {

  /// Read `NetAddress` from buffer.
  /// - Returns: If success return `NetAddress` else return nil for need more bytes.
  public mutating func readAddress() throws -> NetAddress? {
    let data = self
    var byteBuffer = ByteBuffer(bytes: data)
    defer {
      self = Data(byteBuffer.readBytes(length: byteBuffer.readableBytes) ?? [])
    }
    return try byteBuffer.readAddress()
  }

  /// Write `NetAddress` to `ByteBuffer`.
  /// - Parameter address: The address waiting to write.
  /// - Returns: Byte count.
  @discardableResult
  public mutating func writeAddress(_ address: NetAddress) -> Int {
    var byteBuffer = ByteBuffer()
    defer {
      append(contentsOf: byteBuffer.readBytes(length: byteBuffer.readableBytes) ?? [])
    }
    return byteBuffer.writeAddress(address)
  }
}

extension String {

  /// Indicate whether string is an IP address.
  /// - Returns: True if the given string is an IP address.
  public func isIPAddress() -> Bool {
    (try? SocketAddress(ipAddress: self, port: 0)) != nil
  }
}
