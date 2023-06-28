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

import XCTest

@testable import NECLICore

final class ProfileSerializationTests: XCTestCase {

  func testSerializeBasicSettings() throws {
    let expectedBasicSettingsJsonString =
      "{\"basicSettings\":{\"dnsServers\":[\"223.5.5.5\",\"114.114.114.114\",\"system\"],\"exceptions\":[\"localhost\",\"*.local\",\"255.255.255.255\\/32\"],\"excludeSimpleHostnames\":true,\"httpListenAddress\":\"127.0.0.1\",\"httpListenPort\":6152,\"logLevel\":\"trace\",\"socksListenAddress\":\"127.0.0.1\",\"socksListenPort\":6153}}"

    let basicSettingsString = """
      [General]
      dns-servers = 223.5.5.5, 114.114.114.114, system
      exceptions = localhost, *.local, 255.255.255.255/32
      exclude-simple-hostnames = true
      http-listen-address = 127.0.0.1
      http-listen-port = 6152
      log-level = trace
      socks-listen-address = 127.0.0.1
      socks-listen-port = 6153
      """

    let jsonObject = try ProfileSerialization.jsonObject(
      with: basicSettingsString.data(using: .utf8)!
    )
    let data = try JSONSerialization.data(withJSONObject: jsonObject, options: .sortedKeys)
    let basicSettingsJsonString = String(data: data, encoding: .utf8)
    XCTAssertEqual(basicSettingsJsonString, expectedBasicSettingsJsonString)

    let jsonData = try ProfileSerialization.data(withJSONObject: jsonObject)
    let basicSettingsString1 = String(data: jsonData, encoding: .utf8)
    XCTAssertEqual(basicSettingsString1, basicSettingsString)
  }

  func testSerializePolicies() throws {
    let expectedPoliciesString =
      "{\"policies\":[{\"name\":\"HTTP\",\"proxy\":{\"port\":8310,\"protocol\":\"http\",\"serverAddress\":\"127.0.0.1\"},\"type\":\"http\"},{\"name\":\"SOCKS\",\"proxy\":{\"password\":\"password\",\"port\":8320,\"protocol\":\"socks5\",\"serverAddress\":\"127.0.0.1\",\"username\":\"Netbot\"},\"type\":\"socks5\"},{\"name\":\"SHADOWSOCKS\",\"proxy\":{\"algorithm\":\"chacha20-poly1305\",\"password\":\"password\",\"port\":8330,\"protocol\":\"ss\",\"serverAddress\":\"127.0.0.1\",\"tfo\":true},\"type\":\"ss\"},{\"name\":\"VMESS\",\"proxy\":{\"port\":8390,\"protocol\":\"vmess\",\"serverAddress\":\"127.0.0.1\",\"username\":\"2EB5690D-225B-4B49-997F-697D5A36CD9D\"},\"type\":\"vmess\"}]}"

    let policiesString = """
      [Policies]
      HTTP = http, port = 8310, protocol = http, server-address = 127.0.0.1
      SOCKS = socks5, password = password, port = 8320, protocol = socks5, server-address = 127.0.0.1, username = Netbot
      SHADOWSOCKS = ss, algorithm = chacha20-poly1305, password = password, port = 8330, protocol = ss, server-address = 127.0.0.1, tfo = true
      VMESS = vmess, port = 8390, protocol = vmess, server-address = 127.0.0.1, username = 2EB5690D-225B-4B49-997F-697D5A36CD9D
      """

    let jsonObject = try ProfileSerialization.jsonObject(
      with: policiesString.data(using: .utf8)!
    )
    let data = try JSONSerialization.data(withJSONObject: jsonObject, options: .sortedKeys)
    let policiesJsonString = String(data: data, encoding: .utf8)
    XCTAssertEqual(policiesJsonString, expectedPoliciesString)

    let jsonData = try ProfileSerialization.data(withJSONObject: jsonObject)
    let policiesString1 = String(data: jsonData, encoding: .utf8)
    XCTAssertEqual(policiesString1, policiesString)
  }

  func testSerializeBuiltinPolicies() throws {
    let expectedPoliciesString =
      "{\"policies\":[{\"name\":\"DIRECT\",\"type\":\"direct\"},{\"name\":\"REJECT\",\"type\":\"reject\"},{\"name\":\"REJECT-TINYGIF\",\"type\":\"reject-tinygif\"}]}"

    let policiesString = """
      [Policies]
      DIRECT = direct
      REJECT = reject
      REJECT-TINYGIF = reject-tinygif
      """

    let jsonObject = try ProfileSerialization.jsonObject(
      with: policiesString.data(using: .utf8)!
    )
    let data = try JSONSerialization.data(withJSONObject: jsonObject, options: .sortedKeys)
    let policiesJsonString = String(data: data, encoding: .utf8)
    XCTAssertEqual(policiesJsonString, expectedPoliciesString)

    let jsonData = try ProfileSerialization.data(withJSONObject: jsonObject)
    let policiesString1 = String(data: jsonData, encoding: .utf8)
    XCTAssertEqual(policiesString1, policiesString)

    // Test serialize policy with builtin policy name must have specified type
    var errorPolicyString = """
      [Policies]
      DIRECT = reject
      """
    XCTAssertThrowsError(
      try ProfileSerialization.jsonObject(
        with: errorPolicyString.data(using: .utf8)!
      )
    )

    errorPolicyString = """
      [Policies]
      REJECT = reject-tinygif
      """
    XCTAssertThrowsError(
      try ProfileSerialization.jsonObject(
        with: errorPolicyString.data(using: .utf8)!
      )
    )

    errorPolicyString = """
      [Policies]
      REJECT-TINYGIF = reject
      """
    XCTAssertThrowsError(
      try ProfileSerialization.jsonObject(
        with: errorPolicyString.data(using: .utf8)!
      )
    )
  }

  func testSerializePolicyGroups() throws {
    let expectedPolicyGroupsJsonString =
      "{\"policies\":[{\"name\":\"HTTP\",\"proxy\":{\"port\":8310,\"protocol\":\"http\",\"serverAddress\":\"127.0.0.1\"},\"type\":\"http\"}],\"policyGroups\":[{\"name\":\"BLOCK\",\"policies\":[\"DIRECT\",\"REJECT\",\"REJECT-TINYGIF\"],\"type\":\"select\"},{\"name\":\"PROXY\",\"policies\":[\"HTTP\"],\"type\":\"select\"}]}"

    let policyGroupsString = """
      [Policies]
      HTTP = http, port = 8310, protocol = http, server-address = 127.0.0.1

      [Policy Group]
      BLOCK = select, policies = DIRECT, REJECT, REJECT-TINYGIF
      PROXY = select, policies = HTTP
      """

    let jsonObject = try ProfileSerialization.jsonObject(
      with: policyGroupsString.data(using: .utf8)!
    )
    let data = try JSONSerialization.data(withJSONObject: jsonObject, options: .sortedKeys)
    let policyGroupsJsonString = String(data: data, encoding: .utf8)
    XCTAssertEqual(policyGroupsJsonString, expectedPolicyGroupsJsonString)

    let jsonData = try ProfileSerialization.data(withJSONObject: jsonObject)
    let policyGroupsString1 = String(data: jsonData, encoding: .utf8)
    XCTAssertEqual(policyGroupsString1, policyGroupsString)
  }

  func testSerializePolicyGroupsWithUnknownPolicy() {
    let policyGroupsString = """
      [Policy Group]
      PROXY = select, policies = HTTP
      """

    XCTAssertThrowsError(
      try ProfileSerialization.jsonObject(with: policyGroupsString.data(using: .utf8)!)
    )
  }

  func testSerializeRules() throws {
    let expectedRulesJsonString =
      "{\"policies\":[{\"name\":\"HTTP\",\"proxy\":{\"port\":8310,\"protocol\":\"http\",\"serverAddress\":\"127.0.0.1\"},\"type\":\"http\"}],\"policyGroups\":[{\"name\":\"BLOCK\",\"policies\":[\"DIRECT\",\"REJECT\",\"REJECT-TINYGIF\"],\"type\":\"select\"},{\"name\":\"PROXY\",\"policies\":[\"HTTP\"],\"type\":\"select\"}],\"routingRules\":[\"DOMAIN-SUFFIX,example.com,DIRECT\",\"RULE-SET,SYSTEM,DIRECT\",\"GEOIP,CN,DIRECT\",\"FINAL,PROXY\"]}"

    let rulesString = """
      [Policies]
      HTTP = http, port = 8310, protocol = http, server-address = 127.0.0.1

      [Policy Group]
      BLOCK = select, policies = DIRECT, REJECT, REJECT-TINYGIF
      PROXY = select, policies = HTTP

      [Rule]
      DOMAIN-SUFFIX,example.com,DIRECT
      RULE-SET,SYSTEM,DIRECT
      GEOIP,CN,DIRECT
      FINAL,PROXY
      """

    let jsonObject = try ProfileSerialization.jsonObject(with: rulesString.data(using: .utf8)!)
    let data = try JSONSerialization.data(withJSONObject: jsonObject, options: .sortedKeys)
    let rulesJsonString = String(data: data, encoding: .utf8)
    XCTAssertEqual(rulesJsonString, expectedRulesJsonString)

    let jsonData = try ProfileSerialization.data(withJSONObject: jsonObject)
    let rulesString1 = String(data: jsonData, encoding: .utf8)
    XCTAssertEqual(rulesString1, rulesString)
  }

  func testSerializeRulesWithUnknownPolicyOrPolicyGroup() {
    let rulesString = """
      [Rule]
      FINAL,PROXY
      """

    XCTAssertThrowsError(
      try ProfileSerialization.jsonObject(with: rulesString.data(using: .utf8)!)
    )
  }

  func testSerializeRulesThatDefineWithPolicy() throws {
    let expectedRulesJsonString =
      "{\"policies\":[{\"name\":\"HTTP\",\"proxy\":{\"port\":8310,\"protocol\":\"http\",\"serverAddress\":\"127.0.0.1\"},\"type\":\"http\"}],\"routingRules\":[\"DOMAIN-SUFFIX,example.com,DIRECT\",\"RULE-SET,SYSTEM,DIRECT\",\"GEOIP,CN,DIRECT\",\"FINAL,HTTP\"]}"

    let rulesString = """
      [Policies]
      HTTP = http, port = 8310, protocol = http, server-address = 127.0.0.1

      [Rule]
      DOMAIN-SUFFIX,example.com,DIRECT
      RULE-SET,SYSTEM,DIRECT
      GEOIP,CN,DIRECT
      FINAL,HTTP
      """

    let jsonObject = try ProfileSerialization.jsonObject(with: rulesString.data(using: .utf8)!)
    let data = try JSONSerialization.data(withJSONObject: jsonObject, options: .sortedKeys)
    let rulesJsonString = String(data: data, encoding: .utf8)

    XCTAssertEqual(rulesJsonString, expectedRulesJsonString)

    let jsonData = try ProfileSerialization.data(withJSONObject: jsonObject)
    let rulesString1 = String(data: jsonData, encoding: .utf8)
    XCTAssertEqual(rulesString1, rulesString)
  }

  func testSerializeRulesThatDefineWithPolicyGroup() throws {
    let expectedRulesJsonString =
      "{\"policies\":[{\"name\":\"HTTP\",\"proxy\":{\"port\":8310,\"protocol\":\"http\",\"serverAddress\":\"127.0.0.1\"},\"type\":\"http\"}],\"policyGroups\":[{\"name\":\"PROXY\",\"policies\":[\"HTTP\"],\"type\":\"select\"}],\"routingRules\":[\"DOMAIN-SUFFIX,example.com,PROXY\",\"RULE-SET,SYSTEM,PROXY\",\"GEOIP,CN,PROXY\",\"FINAL,PROXY\"]}"

    let rulesString = """
      [Policies]
      HTTP = http, port = 8310, protocol = http, server-address = 127.0.0.1

      [Policy Group]
      PROXY = select, policies = HTTP

      [Rule]
      DOMAIN-SUFFIX,example.com,PROXY
      RULE-SET,SYSTEM,PROXY
      GEOIP,CN,PROXY
      FINAL,PROXY
      """

    let jsonObject = try ProfileSerialization.jsonObject(with: rulesString.data(using: .utf8)!)
    let data = try JSONSerialization.data(withJSONObject: jsonObject, options: .sortedKeys)
    let rulesJsonString = String(data: data, encoding: .utf8)
    XCTAssertEqual(rulesJsonString, expectedRulesJsonString)

    let jsonData = try ProfileSerialization.data(withJSONObject: jsonObject)
    let rulesString1 = String(data: jsonData, encoding: .utf8)
    XCTAssertEqual(rulesString1, rulesString)
  }

  func testSerializeManInTheMiddleSettings() throws {
    let expectedManInTheMiddleSettingsJsonString =
      "{\"manInTheMiddleSettings\":{\"base64EncodedP12String\":\"MIIKPwIBAzCCCgYGCSqGSIb3DQEHAaCCCfc\",\"hostnames\":[\"*.example.com\"],\"passphrase\":\"CS2UNBDR\",\"skipCertificateVerification\":true}}"

    let manInTheMiddleSettingsString = """
      [MitM]
      base64-encoded-p12-string = MIIKPwIBAzCCCgYGCSqGSIb3DQEHAaCCCfc
      hostnames = *.example.com
      passphrase = CS2UNBDR
      skip-certificate-verification = true
      """

    let jsonObject = try ProfileSerialization.jsonObject(
      with: manInTheMiddleSettingsString.data(using: .utf8)!
    )
    let data = try JSONSerialization.data(withJSONObject: jsonObject, options: .sortedKeys)
    let manInTheMiddleSettingsJsonString = String(data: data, encoding: .utf8)
    XCTAssertEqual(manInTheMiddleSettingsJsonString, expectedManInTheMiddleSettingsJsonString)

    let jsonData = try ProfileSerialization.data(withJSONObject: jsonObject)
    let manInTheMiddleSettingsString1 = String(data: jsonData, encoding: .utf8)
    XCTAssertEqual(manInTheMiddleSettingsString1, manInTheMiddleSettingsString)
  }
}
