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

#if canImport(Network)
@_exported import Network
#else
@preconcurrency import Foundation
import NIOCore

public protocol OS_nw_endpoint: NSObjectProtocol, Sendable {
}

// swift-format-ignore: TypeNamesShouldBeCapitalized
public typealias nw_endpoint_t = any OS_nw_endpoint

public enum NWEndpoint: Hashable, Sendable {

  /// A host port endpoint represents an endpoint defined by the host and port.
  case hostPort(host: Host, port: Port)

  /// A service endpoint represents a Bonjour service
  case service(name: String, type: String, domain: String, interface: NWInterface?)

  /// A unix endpoint represents a path that supports connections using AF_UNIX domain sockets.
  case unix(path: String)

  /// A URL endpoint represents an endpoint defined by a URL. Connection will parse out
  /// the hostname and appropriate port. Note that the scheme will not influence the protocol
  /// stack being used.
  case url(URL)

  case opaque(nw_endpoint_t)

  /// A Host is a name or address
  public enum Host: Hashable, ExpressibleByStringLiteral, Sendable {

    /// A type that represents a string literal.
    ///
    /// Valid types for `StringLiteralType` are `String` and `StaticString`.
    public typealias StringLiteralType = String

    /// A host specified as a name and optional interface scope
    case name(String, NWInterface?)

    /// A host specified as an IPv4 address
    case ipv4(IPv4Address)

    /// A host specified an an IPv6 address
    case ipv6(IPv6Address)

    /// Creates an instance initialized to the given string value.
    ///
    /// - Parameter value: The value of the new instance.
    public init(stringLiteral: NWEndpoint.Host.StringLiteralType) {
      self.init(stringLiteral)
    }

    /// Create a host from a string.
    ///
    /// This is the preferred way to create a host. If the string is an IPv4 address literal ("198.51.100.2"), an
    /// IPv4 host will be created. If the string is an IPv6 address literal ("2001:DB8::2", "fe80::1%lo", etc), an IPv6
    /// host will be created. If the string is an IPv4 mapped IPv6 address literal ("::ffff:198.51.100.2") an IPv4
    /// host will be created. Otherwise, a named host will be created.
    ///
    /// - Parameter string: An IPv4 address literal, an IPv6 address literal, or a hostname.
    /// - Returns: A Host object
    public init(_ string: String) {
      if let address = IPv4Address(string) {
        self = .ipv4(address)
        return
      }

      if let address = IPv6Address(string) {
        self = .ipv6(address)
        return
      }

      self = .name(string, nil)
    }

    /// A type that represents an extended grapheme cluster literal.
    ///
    /// Valid types for `ExtendedGraphemeClusterLiteralType` are `Character`,
    /// `String`, and `StaticString`.
    public typealias ExtendedGraphemeClusterLiteralType = NWEndpoint.Host.StringLiteralType

    /// A type that represents a Unicode scalar literal.
    ///
    /// Valid types for `UnicodeScalarLiteralType` are `Unicode.Scalar`,
    /// `Character`, `String`, and `StaticString`.
    public typealias UnicodeScalarLiteralType = NWEndpoint.Host.StringLiteralType
  }

  /// A network port (TCP or UDP)
  public struct Port: Hashable, CustomDebugStringConvertible, ExpressibleByIntegerLiteral,
    RawRepresentable, Sendable
  {

    /// A type that represents an integer literal.
    ///
    /// The standard library integer and floating-point types are all valid types
    /// for `IntegerLiteralType`.
    public typealias IntegerLiteralType = UInt16

    public static let any: NWEndpoint.Port = 0

    public static let ssh: NWEndpoint.Port = 22

    public static let smtp: NWEndpoint.Port = 25

    public static let http: NWEndpoint.Port = 80

    public static let pop: NWEndpoint.Port = 110

    public static let imap: NWEndpoint.Port = 143

    public static let https: NWEndpoint.Port = 443

    public static let imaps: NWEndpoint.Port = 993

    public static let socks: NWEndpoint.Port = 1080

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
    public init(integerLiteral value: NWEndpoint.Port.IntegerLiteralType) {
      _rawValue = value
    }

    /// Creates a new instance with the specified raw value.
    ///
    /// If there is no value of the type that corresponds with the specified raw
    /// value, this initializer returns `nil`. For example:
    ///
    ///     enum PaperSize: String {
    ///         case A4, A5, Letter, Legal
    ///     }
    ///
    ///     print(PaperSize(rawValue: "Legal"))
    ///     // Prints "Optional("PaperSize.Legal")"
    ///
    ///     print(PaperSize(rawValue: "Tabloid"))
    ///     // Prints "nil"
    ///
    /// - Parameter rawValue: The raw value to use for the new instance.
    public init?(rawValue: UInt16) {
      _rawValue = rawValue
    }

    public var debugDescription: String {
      String(rawValue)
    }

    /// The raw type that can be used to represent all values of the conforming
    /// type.
    ///
    /// Every distinct value of the conforming type has a corresponding unique
    /// value of the `RawValue` type, but there may be values of the `RawValue`
    /// type that don't have a corresponding value of the conforming type.
    public typealias RawValue = UInt16
  }

  public static func == (lhs: NWEndpoint, rhs: NWEndpoint) -> Bool {
    switch (lhs, rhs) {
    case (.hostPort(host: let lh, port: let lp), .hostPort(host: let rh, port: let rp)):
      return lh == rh && lp == rp
    case (
      .service(name: let ln, type: let lt, domain: let ld, interface: let li),
      .service(name: let rn, type: let rt, domain: let rd, interface: let ri)
    ):
      return ln == rn && lt == rt && ld == rd && li == ri
    case (.unix(path: let lp), .unix(path: let rp)):
      return lp == rp
    case (.url(let lu), .url(let ru)):
      return lu == ru
    case (.opaque(let le), .opaque(let re)):
      return le.isEqual(re)
    default:
      return false
    }
  }

  public func hash(into hasher: inout Hasher) {
    switch self {
    case .hostPort(let host, let port):
      hasher.combine(host)
      hasher.combine(port)
    case .service(let name, let type, let domain, let interface):
      hasher.combine(name)
      hasher.combine(type)
      hasher.combine(domain)
      hasher.combine(interface)
    case .unix(let path):
      hasher.combine(path)
    case .url(let url):
      hasher.combine(url)
    case .opaque(let p):
      hasher.combine(p.hash)
    }
  }
}

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
  /// - Returns: An IPv4Address or nil if the Data parameter did not contain an IPv4 address.
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
    guard let description = address.ipAddress else {
      preconditionFailure("")
    }
    return description
  }
}

/// IPv6Address
/// Base type to hold an IPv6 address and convert between strings and raw bytes.
/// Note that an IPv6 address may be scoped to an interface.
public struct IPv6Address: IPAddress, Hashable, CustomDebugStringConvertible {

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

  /// Fetch the raw address (sixteen bytes)
  public var rawValue: Data { _rawValue }
  private var _rawValue: Data

  public var debugDescription: String {
    let packedIPAddress = ByteBuffer(bytes: rawValue)
    let address = try! SocketAddress(packedIPAddress: packedIPAddress, port: 0)
    guard let description = address.ipAddress else {
      preconditionFailure("")
    }
    return description
  }
}

public struct NWInterface: Hashable, Sendable {}
#endif
