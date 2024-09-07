//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2024 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation
import NEAddressProcessing
import NIOCore

// FIXME: Duplicated with NESOCKS.

/// Address identifier defined in RFC 1928.
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
  mutating func parseUnwinding<T>(_ closure: (inout ByteBuffer) throws -> T?) rethrows -> T? {
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

  /// Read `Address` from buffer which contains RFC1928 request address formatted bytes.
  ///
  /// This method is used to parse address that encoded as SOCKS address defined in RFC 1928.
  ///
  /// - Throws: May throw  `SocketAddressError.unsupported` if address type is illegal,
  ///     or `SocketAddressError.FailedToParseIPByteBuffer(address:)` if failed to parse ipaddress.
  /// - Returns: If success return `NetAddress` else return nil for need more bytes.
  mutating func readRFC1928RequestAddressAsEndpoint() throws -> Address? {
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
        guard let slice = buffer.readLengthPrefixedSlice(as: UInt8.self),
          let port = buffer.readInteger(as: UInt16.self)
        else {
          return nil
        }
        return .hostPort(host: .name(String(buffer: slice)), port: .init(rawValue: port))
      case .v4:
        guard let packedIPAddress = buffer.readSlice(length: 4),
          let address = IPv4Address(Data(Array(buffer: packedIPAddress))),
          let port = buffer.readInteger(as: UInt16.self)
        else {
          return nil
        }
        return .hostPort(host: .ipv4(address), port: .init(rawValue: port))
      case .v6:
        guard let packedIPAddress = buffer.readSlice(length: 16),
          let address = IPv6Address(Data(Array(buffer: packedIPAddress))),
          let port = buffer.readInteger(as: UInt16.self)
        else {
          return nil
        }
        return .hostPort(host: .ipv6(address), port: .init(rawValue: port))
      }
    }
  }

  /// Write `NWEndpoint` to `ByteBuffer` in RFC1928 request address format.
  /// - Parameter address: The address waiting to write.
  /// - Returns: Byte count.
  @discardableResult
  mutating func writeEndpointInRFC1928RequestAddressFormat(_ address: Address) -> Int {
    var totalBytesWritten = 0

    switch address {
    case .hostPort(let host, let port):
      switch host {
      case .ipv4(let address):
        totalBytesWritten += writeInteger(AddressFlag.v4.rawValue)
        totalBytesWritten += writeBytes(address.rawValue)
        totalBytesWritten += writeInteger(port.rawValue)
      case .ipv6(let address):
        totalBytesWritten += writeInteger(AddressFlag.v6.rawValue)
        totalBytesWritten += writeBytes(address.rawValue)
        totalBytesWritten += writeInteger(port.rawValue)
      case .name(let name):
        totalBytesWritten += writeInteger(AddressFlag.domain.rawValue)
        // swift-format-ignore: NeverUseForceTry
        totalBytesWritten += try! writeLengthPrefixed(as: UInt8.self) {
          $0.writeString(name)
        }
        totalBytesWritten += writeInteger(port.rawValue)
      }
    case .unix, .url:
      fatalError("\(#function) unsupported endpoint")
    }
    return totalBytesWritten
  }
}
