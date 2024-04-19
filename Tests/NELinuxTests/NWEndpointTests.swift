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

import XCTest
import _NELinux

final class NWEndpointTests: XCTestCase {

  func testCreateIPv4AddressFromString() {
    let address = IPv4Address("0.0.0.1")
    let expectedAddress = Data([0x00, 0x00, 0x00, 0x01])

    XCTAssertNotNil(address)
    XCTAssertEqual(address?.rawValue, expectedAddress)
  }

  func testCreateIPv4AddressFromRawData() {
    XCTAssertNotNil(IPv4Address(Data([0x00, 0x00, 0x00, 0x01])))
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
    XCTAssertEqual(NWEndpoint.Host(name), .name(name, nil))

    let ipv6 = "::"
    XCTAssertEqual(NWEndpoint.Host(ipv6), .ipv6(IPv6Address(ipv6)!))

    let ipv4 = "0.0.0.0"
    XCTAssertEqual(NWEndpoint.Host(ipv4), .ipv4(IPv4Address(ipv4)!))
  }

  func testCreateHostFromStringLiteral() {
    var host: NWEndpoint.Host = "swift.org"
    XCTAssertEqual(host, .name("swift.org", nil))

    host = "::"
    XCTAssertEqual(host, .ipv6(IPv6Address("::")!))

    host = "0.0.0.0"
    XCTAssertEqual(host, .ipv4(IPv4Address("0.0.0.0")!))
  }

  func testHostEquatable() {
    let name = NWEndpoint.Host.name("swift.org", nil)
    let ipv4 = NWEndpoint.Host.ipv4(IPv4Address("0.0.0.0")!)
    let ipv6 = NWEndpoint.Host.ipv6(IPv6Address("::")!)

    XCTAssertEqual(NWEndpoint.Host.name("swift.org", nil), name)
    XCTAssertEqual(NWEndpoint.Host.ipv4(IPv4Address("0.0.0.0")!), ipv4)
    XCTAssertEqual(NWEndpoint.Host.ipv6(IPv6Address("::")!), ipv6)
    XCTAssertNotEqual(name, ipv4)
    XCTAssertNotEqual(name, ipv6)
    XCTAssertNotEqual(ipv4, ipv6)
  }

  func testHostHashable() {
    let name = NWEndpoint.Host.name("swift.org", nil)
    let name2 = NWEndpoint.Host.name("swift.org", nil)
    let ipv4 = NWEndpoint.Host.ipv4(IPv4Address("0.0.0.0")!)
    let ipv6 = NWEndpoint.Host.ipv6(IPv6Address("::")!)
    let set = Set([name, name2, ipv4, ipv6])

    XCTAssertEqual(set.count, 3)
    XCTAssertTrue(set.contains(name))
    XCTAssertTrue(set.contains(name2))
    XCTAssertTrue(set.contains(ipv4))
    XCTAssertTrue(set.contains(ipv6))
  }

  func testCreatePortFromUInt16RawValue() {
    let port = NWEndpoint.Port(rawValue: 443)
    XCTAssertNotNil(port)
    XCTAssertEqual(port?.rawValue, 443)
  }

  func testCreatePortFromIntegerLIteral() {
    let port: NWEndpoint.Port = 443
    XCTAssertEqual(port.rawValue, 443)
  }

  func testPortEquatable() {
    let port: NWEndpoint.Port = 443
    XCTAssertEqual(NWEndpoint.Port(rawValue: 443)!, port)
    XCTAssertNotEqual(NWEndpoint.Port(rawValue: 80)!, port)
  }

  func testPortHashable() {
    let a: NWEndpoint.Port = 443
    let b: NWEndpoint.Port = 443
    let c: NWEndpoint.Port = 80
    let set = Set([a, b, c])

    XCTAssertEqual(set.count, 2)
    XCTAssertTrue(set.contains(a))
    XCTAssertTrue(set.contains(b))
    XCTAssertTrue(set.contains(c))
  }

  func testPortCustomDebugStringConvertible() {
    let port: NWEndpoint.Port = 443
    XCTAssertEqual(port.debugDescription, "443")
  }

  func testPortRawRepresentable() {
    let port = NWEndpoint.Port(rawValue: 443)
    XCTAssertNotNil(port)
    XCTAssertEqual(try! XCTUnwrap(port).rawValue, 443)
  }

  func testHostPortEndpointEquatableAddHashable() {
    let a = NWEndpoint.hostPort(host: "::", port: 0)
    let b = NWEndpoint.hostPort(host: "::", port: 0)
    let c = NWEndpoint.hostPort(host: "::", port: 1)
    let d = NWEndpoint.hostPort(host: "0.0.0.0", port: 0)
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
}
