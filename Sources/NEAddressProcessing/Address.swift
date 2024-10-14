//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2024 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import struct NIOCore.ByteBuffer
import enum NIOCore.SocketAddress

#if canImport(Darwin)
  import Foundation
#else
  @preconcurrency import Foundation
#endif

/// An IP address
public protocol IPAddress: Sendable {

  /// Fetch the raw address as data
  var rawValue: Data { get }

  /// Create an IP address from data. The length of the data must
  /// match the expected length of addresses in the address family
  /// (four bytes for IPv4, and sixteen bytes for IPv6)
  init?(_ rawValue: Data)

  /// Create an IP address from an address literal string.
  /// If the string contains '%' to indicate an interface, the interface will be
  /// associated with the address, such as "::1%lo0" being associated with the loopback
  /// interface.
  /// This function does not perform host name to address resolution. This is the same as calling getaddrinfo
  /// and using AI_NUMERICHOST.
  init?(_ string: String)
}

/// IPv4Address
/// Base type to hold an IPv4 address and convert between strings and raw bytes.
/// Note that an IPv4 address may be scoped to an interface.
public struct IPv4Address: IPAddress, Hashable, CustomDebugStringConvertible {

  /// Fetch the raw address (four bytes)
  public var rawValue: Data { _rawValue }
  private var _rawValue: Data

  /// Create an IPv4 address from a 4-byte data.
  ///
  /// - Parameter rawValue: The raw bytes of the IPv4 address, must be exactly 4 bytes or init will fail.
  public init?(_ rawValue: Data) {
    guard rawValue.count == 4 else {
      return nil
    }

    let buffer = ByteBuffer(bytes: rawValue)
    guard case .v4 = try? SocketAddress(packedIPAddress: buffer, port: 0) else {
      return nil
    }

    _rawValue = rawValue
  }

  /// Create an IPv4 address from an address literal string.
  ///
  /// This function does not perform host name to address resolution. This is the same as calling getaddrinfo
  /// and using AI_NUMERICHOST.
  ///
  /// - Parameter string: An IPv4 address literal string such as "127.0.0.1".
  /// - Returns: An IPv4Address or nil if the string parameter did not
  /// contain an IPv4 address literal.
  public init?(_ string: String) {
    guard case .v4(let v4) = try? SocketAddress(ipAddress: string, port: 0) else {
      return nil
    }
    var localAddr = v4.address
    _rawValue = withUnsafeBytes(of: &localAddr.sin_addr) {
      precondition($0.count == 4)
      return Data(bytes: $0.baseAddress!, count: $0.count)
    }
  }

  public var debugDescription: String {
    let packedIPAddress = ByteBuffer(bytes: rawValue)
    let address = try! SocketAddress(packedIPAddress: packedIPAddress, port: 0)
    return address.ipAddress!
  }
}

/// IPv6Address
/// Base type to hold an IPv6 address and convert between strings and raw bytes.
/// Note that an IPv6 address may be scoped to an interface.
public struct IPv6Address: IPAddress, Hashable, CustomDebugStringConvertible {

  /// Fetch the raw address (sixteen bytes)
  public var rawValue: Data { _rawValue }
  private var _rawValue: Data

  /// Create an IPv6 from a raw 16 byte value and optional interface
  ///
  /// - Parameter rawValue: A 16 byte IPv6 address
  /// - Parameter interface: An optional interface the address is scoped to. Defaults to nil.
  /// - Returns: nil unless the raw data contained an IPv6 address
  public init?(_ rawValue: Data) {
    guard rawValue.count == 16 else {
      return nil
    }

    let buffer = ByteBuffer(bytes: rawValue)
    guard case .v6 = try? SocketAddress(packedIPAddress: buffer, port: 0) else {
      return nil
    }

    _rawValue = rawValue
  }

  /// Create an IPv6 address from a string literal such as "2001:DB8::5"
  ///
  /// This function does not perform hostname resolution. This is similar to calling getaddrinfo with
  /// AI_NUMERICHOST.
  ///
  /// - Parameter string: An IPv6 address literal string.
  /// - Returns: nil unless the string contained an IPv6 literal
  public init?(_ string: String) {
    guard case .v6(let v6) = try? SocketAddress(ipAddress: string, port: 0) else {
      return nil
    }
    var localAddr = v6.address
    _rawValue = withUnsafeBytes(of: &localAddr.sin6_addr) {
      precondition($0.count == 16)
      return Data(bytes: $0.baseAddress!, count: $0.count)
    }
  }

  public var debugDescription: String {
    let packedIPAddress = ByteBuffer(bytes: rawValue)
    let address = try! SocketAddress(packedIPAddress: packedIPAddress, port: 0)
    return address.ipAddress!
  }
}

public enum Address: Hashable, Sendable {

  /// A host port endpoint represents an endpoint defined by the host and port.
  case hostPort(host: Host, port: Port)

  /// A unix endpoint represents a path that supports connections using AF_UNIX domain sockets.
  case unix(path: String)

  /// A URL endpoint represents an endpoint defined by a URL. Connection will parse out
  /// the hostname and appropriate port. Note that the scheme will not influence the protocol
  /// stack being used.
  case url(URL)

  /// A Host is a name or address
  public enum Host: Hashable, ExpressibleByStringLiteral, Sendable {

    /// A host specified as a name and optional interface scope
    case name(String)

    /// A host specified as an IPv4 address
    case ipv4(IPv4Address)

    /// A host specified an an IPv6 address
    case ipv6(IPv6Address)

    /// Creates an instance initialized to the given string value.
    ///
    /// - Parameter value: The value of the new instance.
    public init(stringLiteral value: String) {
      self.init(value)
    }

    /// Create a host from a string.
    ///
    /// This is the preferred way to create a host. If the string is an IPv4 address literal ("198.51.100.2"), an
    /// IPv4 host will be created. If the string is an IPv6 address literal ("2001:DB8::2", "fe80::1%lo", etc), an IPv6
    /// host will be created. If the string is an IPv4 mapped IPv6 address literal ("::ffff:198.51.100.2") an IPv4
    /// host will be created. Otherwise, a named host will be created.
    ///
    /// - Parameter string: An IPv4 address literal, an IPv6 address literal, or a hostname.
    public init(_ string: String) {
      if let address = IPv4Address(string) {
        self = .ipv4(address)
        return
      }

      if let address = IPv6Address(string) {
        self = .ipv6(address)
        return
      }

      self = .name(string)
    }
  }

  /// A network port (TCP or UDP)
  public struct Port: Hashable, CustomDebugStringConvertible, ExpressibleByIntegerLiteral,
    RawRepresentable, Sendable
  {

    public static let any: Port = 0

    public static let ssh: Port = 22

    public static let smtp: Port = 25

    public static let http: Port = 80

    public static let pop: Port = 110

    public static let imap: Port = 143

    public static let https: Port = 443

    public static let imaps: Port = 993

    public static let socks: Port = 1080

    /// The corresponding value of the raw type.
    ///
    /// A new instance initialized with `rawValue` will be equivalent to this
    /// instance. For example:
    ///
    ///     enum PaperSize: String {
    ///         case A4, A5, Letter, Legal
    ///     }
    ///
    ///     let selectedSize = PaperSize.Letter
    ///     print(selectedSize.rawValue)
    ///     // Prints "Letter"
    ///
    ///     print(selectedSize == PaperSize(rawValue: selectedSize.rawValue)!)
    ///     // Prints "true"
    public var rawValue: UInt16 { _rawValue }
    private var _rawValue: UInt16

    /// Creates an instance initialized to the specified integer value.
    ///
    /// Do not call this initializer directly. Instead, initialize a variable or
    /// constant using an integer literal. For example:
    ///
    ///     let x = 23
    ///
    /// In this example, the assignment to the `x` constant calls this integer
    /// literal initializer behind the scenes.
    ///
    /// - Parameter value: The value to create.
    public init(integerLiteral value: UInt16) {
      _rawValue = value
    }

    public init(rawValue: UInt16) {
      _rawValue = rawValue
    }

    public var debugDescription: String {
      String(rawValue)
    }
  }

  /// Get the host associated with the address, if defined.
  public func host(percentEncoded: Bool = true) -> String? {
    switch self {
    case .hostPort(let host, port: _):
      switch host {
      case .name(let name):
        guard percentEncoded else {
          return name.removingPercentEncoding
        }
        return name.addingPercentEncoding(withAllowedCharacters: .urlHostAllowed)
      case .ipv4(let address):
        guard percentEncoded else {
          return address.debugDescription.removingPercentEncoding
        }
        return address.debugDescription.addingPercentEncoding(
          withAllowedCharacters: .urlHostAllowed
        )
      case .ipv6(let address):
        guard percentEncoded else {
          return address.debugDescription.removingPercentEncoding
        }
        return address.debugDescription.addingPercentEncoding(
          withAllowedCharacters: .urlHostAllowed
        )
      }
    case .url(let url):
      #if canImport(Darwin)
        if #available(iOS 16.0, macOS 13.0, tvOS 16.0, watchOS 9.0, *) {
          return url.host(percentEncoded: percentEncoded)
        } else {
          guard percentEncoded else {
            return url.host?.removingPercentEncoding
          }
          return url.host?.addingPercentEncoding(withAllowedCharacters: .urlHostAllowed)
        }
      #else
        guard percentEncoded else {
          return url.host?.removingPercentEncoding
        }
        return url.host?.addingPercentEncoding(withAllowedCharacters: .urlHostAllowed)
      #endif
    case .unix:
      return nil
    }
  }

  /// Get the port associated with the address, if defined.
  public var port: Int? {
    switch self {
    case .hostPort(_, let port):
      return Int(port.rawValue)
    case .unix:
      return nil
    case .url(let url):
      return url.port
    }
  }
}
