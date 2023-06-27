//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2023 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NEAppEssentials
import XCTest

@testable import NECLICore

final class BasicSettingsTests: XCTestCase {

  func testDecodeBasicSettings() throws {
    let basicSettingsString =
      "{\"dnsServers\":[\"8.8.8.8\"],\"exceptions\":[\"localhost\"],\"excludeSimpleHostnames\":true,\"httpListenAddress\":\"127.0.0.1\",\"httpListenPort\":6152,\"logLevel\":\"debug\",\"socksListenAddress\":\"127.0.0.1\",\"socksListenPort\":6153}"

    let basicSettings = try JSONDecoder().decode(
      BasicSettings.self,
      from: basicSettingsString.data(using: .utf8)!
    )

    XCTAssertEqual(basicSettings.logLevel, .debug)
    XCTAssertEqual(basicSettings.dnsServers, ["8.8.8.8"])
    XCTAssertEqual(basicSettings.exceptions, ["localhost"])
    XCTAssertEqual(basicSettings.httpListenAddress, "127.0.0.1")
    XCTAssertEqual(basicSettings.httpListenPort, 6152)
    XCTAssertEqual(basicSettings.socksListenAddress, "127.0.0.1")
    XCTAssertEqual(basicSettings.socksListenPort, 6153)
    XCTAssertEqual(basicSettings.excludeSimpleHostnames, true)
  }

  func testDefaultValueWorksWhenDecodingBasicSettings() throws {
    let basicSettingsString = "{}"

    let basicSettings = try JSONDecoder().decode(
      BasicSettings.self,
      from: basicSettingsString.data(using: .utf8)!
    )

    XCTAssertEqual(basicSettings.logLevel, .info)
    XCTAssertEqual(basicSettings.dnsServers, [])
    XCTAssertEqual(basicSettings.exceptions, [])
    XCTAssertNil(basicSettings.httpListenAddress)
    XCTAssertNil(basicSettings.httpListenPort)
    XCTAssertNil(basicSettings.socksListenAddress)
    XCTAssertNil(basicSettings.socksListenPort)
    XCTAssertEqual(basicSettings.excludeSimpleHostnames, false)
  }

  func testEncodeBasicSettings() throws {
    let expectedBasicSettingsString =
      "{\"dnsServers\":[\"8.8.8.8\"],\"exceptions\":[\"localhost\"],\"excludeSimpleHostnames\":true,\"httpListenAddress\":\"127.0.0.1\",\"httpListenPort\":6152,\"logLevel\":\"debug\",\"socksListenAddress\":\"127.0.0.1\",\"socksListenPort\":6153}"

    let basicSettings = BasicSettings(
      logLevel: .debug,
      dnsServers: ["8.8.8.8"],
      exceptions: ["localhost"],
      httpListenAddress: "127.0.0.1",
      httpListenPort: 6152,
      socksListenAddress: "127.0.0.1",
      socksListenPort: 6153,
      excludeSimpleHostnames: true
    )

    let encoder = JSONEncoder()
    encoder.outputFormatting = .sortedKeys
    let basicSettingsString = String(data: try encoder.encode(basicSettings), encoding: .utf8)

    XCTAssertEqual(basicSettingsString, expectedBasicSettingsString)
  }

  func testEncodeDefaultBasicSettings() throws {
    let expectedBasicSettingsString =
      "{\"dnsServers\":[],\"exceptions\":[],\"excludeSimpleHostnames\":false,\"logLevel\":\"info\"}"

    let basicSettings = BasicSettings()

    let encoder = JSONEncoder()
    encoder.outputFormatting = .sortedKeys
    let basicSettingsString = String(data: try encoder.encode(basicSettings), encoding: .utf8)

    XCTAssertEqual(basicSettingsString, expectedBasicSettingsString)
  }
}
