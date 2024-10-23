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

import NEAddressProcessing
import XCTest

final class AddressTests: XCTestCase {

  func testCreateIPv4AddressFromString() {
    let address = IPv4Address("0.0.0.1")
    let expectedAddress = Data([0x00, 0x00, 0x00, 0x01])

    XCTAssertNotNil(address)
    XCTAssertEqual(address?.rawValue, expectedAddress)
  }

  func testCreateIPv4AddressFromRawData() {
    XCTAssertNotNil(IPv4Address(Data([0x00, 0x00, 0x00, 0x01])))
  }

  func testCreateIPv4AddressFromInvalidData() {
    XCTAssertNil(IPv4Address(Data([0x00, 0x00, 0x00])))
    XCTAssertNil(IPv4Address(Data([0x00, 0x00, 0x00, 0x00, 0x00])))
  }

  func testIPv4AddressEquatable() {
    XCTAssertEqual(IPv4Address("0.0.0.1"), IPv4Address("0.0.0.1"))
  }

  func testIPv4AddressHashable() {
    let a = IPv4Address("0.0.0.1")
    let b = IPv4Address("0.0.0.1")
    let c = IPv4Address("1.102.103.104")

    let set = Set([a, b, c])
    XCTAssertEqual(set.count, 2)
    XCTAssertTrue(set.contains(a))
    XCTAssertTrue(set.contains(b))
    XCTAssertTrue(set.contains(c))
  }

  func testIPv4AddressCustomDebugStringConvertible() {
    XCTAssertEqual(IPv4Address("0.0.0.1")?.debugDescription, "0.0.0.1")
  }

  func testCreateIPv6AddressFromString() {
    let address = IPv6Address("fe80::5")
    let expectedAddress = Data([
      0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x05,
    ])
    XCTAssertNotNil(address)
    XCTAssertEqual(address?.rawValue, expectedAddress)
  }

  func testCreateIPv6AddressFromRawData() {
    XCTAssertNotNil(
      IPv6Address(
        Data([
          0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x05,
        ])
      )
    )
  }

  func testCreateIPv6AddressFromInvalidRawData() {
    XCTAssertNil(
      IPv6Address(Data([0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))
    )

    XCTAssertNil(
      IPv6Address(
        Data([
          0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x05, 0x01, 0x1a,
        ])
      )
    )
  }

  func testIPv6AddressEquatable() {
    XCTAssertEqual(IPv4Address("::"), IPv4Address("::"))
  }

  func testIPv6AddressHashable() {
    let a = IPv6Address("::")
    let b = IPv6Address("::")
    let c = IPv6Address("fe80::5")

    let set = Set([a, b, c])
    XCTAssertEqual(set.count, 2)
    XCTAssertTrue(set.contains(a))
    XCTAssertTrue(set.contains(b))
    XCTAssertTrue(set.contains(c))
  }

  func testIPv6AddressCustomDebugStringConvertible() {
    XCTAssertEqual(IPv6Address("fe80::5")?.debugDescription, "fe80::5")
  }

  func testCreateHostFromString() {
    let name = "swift.org"
    XCTAssertEqual(Address.Host(name), .name(name))

    let ipv6 = "::"
    XCTAssertEqual(Address.Host(ipv6), .ipv6(IPv6Address(ipv6)!))

    let ipv4 = "0.0.0.0"
    XCTAssertEqual(Address.Host(ipv4), .ipv4(IPv4Address(ipv4)!))
  }

  func testCreateHostFromStringLiteral() {
    var host: Address.Host = "swift.org"
    XCTAssertEqual(host, .name("swift.org"))

    host = "::"
    XCTAssertEqual(host, .ipv6(IPv6Address("::")!))

    host = "0.0.0.0"
    XCTAssertEqual(host, .ipv4(IPv4Address("0.0.0.0")!))
  }

  func testHostEquatable() {
    let name = Address.Host.name("swift.org")
    let ipv4 = Address.Host.ipv4(IPv4Address("0.0.0.0")!)
    let ipv6 = Address.Host.ipv6(IPv6Address("::")!)

    XCTAssertEqual(Address.Host.name("swift.org"), name)
    XCTAssertEqual(Address.Host.ipv4(IPv4Address("0.0.0.0")!), ipv4)
    XCTAssertEqual(Address.Host.ipv6(IPv6Address("::")!), ipv6)
    XCTAssertNotEqual(name, ipv4)
    XCTAssertNotEqual(name, ipv6)
    XCTAssertNotEqual(ipv4, ipv6)
  }

  func testHostHashable() {
    let name = Address.Host.name("swift.org")
    let name2 = Address.Host.name("swift.org")
    let ipv4 = Address.Host.ipv4(IPv4Address("0.0.0.0")!)
    let ipv6 = Address.Host.ipv6(IPv6Address("::")!)
    let set = Set([name, name2, ipv4, ipv6])

    XCTAssertEqual(set.count, 3)
    XCTAssertTrue(set.contains(name))
    XCTAssertTrue(set.contains(name2))
    XCTAssertTrue(set.contains(ipv4))
    XCTAssertTrue(set.contains(ipv6))
  }

  func testHostCustomDebugStringConvertible() {
    var host: Address.Host = "swift.org"
    XCTAssertEqual(host.debugDescription, "swift.org")
    host = "127.0.0.1"
    XCTAssertEqual(host.debugDescription, "127.0.0.1")
    host = "fe80::5"
    XCTAssertEqual(host.debugDescription, "fe80::5")
  }

  func testCreatePortFromUInt16RawValue() {
    let port = Address.Port(rawValue: 443)
    XCTAssertNotNil(port)
    XCTAssertEqual(port.rawValue, 443)
  }

  func testCreatePortFromIntegerLIteral() {
    let port: Address.Port = 443
    XCTAssertEqual(port.rawValue, 443)
  }

  func testPortEquatable() {
    let port: Address.Port = 443
    XCTAssertEqual(Address.Port(rawValue: 443), port)
    XCTAssertNotEqual(Address.Port(rawValue: 80), port)
  }

  func testPortHashable() {
    let a: Address.Port = 443
    let b: Address.Port = 443
    let c: Address.Port = 80
    let set = Set([a, b, c])

    XCTAssertEqual(set.count, 2)
    XCTAssertTrue(set.contains(a))
    XCTAssertTrue(set.contains(b))
    XCTAssertTrue(set.contains(c))
  }

  func testPortCustomDebugStringConvertible() {
    let port: Address.Port = 443
    XCTAssertEqual(port.debugDescription, "443")
  }

  func testPortRawRepresentable() {
    let port = Address.Port(rawValue: 443)
    XCTAssertNotNil(port)
    XCTAssertEqual(try! XCTUnwrap(port).rawValue, 443)
  }

  func testHostPortAddressEquatableAndHashable() {
    let a = Address.hostPort(host: "::", port: 0)
    let b = Address.hostPort(host: "::", port: 0)
    let c = Address.hostPort(host: "::", port: 1)
    let d = Address.hostPort(host: "0.0.0.0", port: 0)
    let set = Set([a, b, c, d])

    XCTAssertEqual(a, b)
    XCTAssertNotEqual(a, c)
    XCTAssertNotEqual(a, d)
    XCTAssertEqual(set.count, 3)
    XCTAssertTrue(set.contains(a))
    XCTAssertTrue(set.contains(b))
    XCTAssertTrue(set.contains(c))
    XCTAssertTrue(set.contains(d))
  }

  func testGetPortFromAddress() {
    var address = Address.hostPort(host: "::", port: 0)
    XCTAssertEqual(address.port, 0)

    address = .unix(path: "var/tmp")
    XCTAssertNil(address.port)

    address = .url(URL(string: "https://example.com:443")!)
    XCTAssertEqual(address.port, 443)
  }

  func testGetHostFromAddress() {
    var address = Address.hostPort(host: "example.com", port: 0)
    XCTAssertEqual(address.host(), "example.com")
    XCTAssertEqual(address.host(percentEncoded: false), "example.com")

    address = Address.hostPort(host: "127.0.0.1", port: 0)
    XCTAssertEqual(address.host(), "127.0.0.1")
    XCTAssertEqual(address.host(percentEncoded: false), "127.0.0.1")

    address = Address.hostPort(host: "::", port: 0)
    XCTAssertEqual(address.host(), "%3A%3A")
    XCTAssertEqual(address.host(percentEncoded: false), "::")

    address = .unix(path: "var/tmp")
    XCTAssertNil(address.host())
    XCTAssertNil(address.host(percentEncoded: false))

    address = .url(URL(string: "https://example.com:443")!)
    XCTAssertEqual(address.host(), "example.com")
    XCTAssertEqual(address.host(percentEncoded: false), "example.com")
  }

  func testAddressHashableConformance() {
    let address = Address.hostPort(host: "swift.org", port: 443)
    let addressCopy = address
    let addresses = Set<Address>([address, addressCopy])
    XCTAssertEqual(addresses, [address])
  }

  func testAddressCustomDebugStringConvertibleConformance() {
    var address = Address.hostPort(host: "swift.org", port: 443)
    XCTAssertEqual(address.debugDescription, "swift.org:443")

    address = Address.unix(path: "/var/run/tmp.sock")
    XCTAssertEqual(address.debugDescription, "/var/run/tmp.sock")

    address = Address.url(URL(string: "https://swift.org:443")!)
    XCTAssertEqual(address.debugDescription, "https://swift.org:443")
  }
}
