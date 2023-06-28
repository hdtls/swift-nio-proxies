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

import NEAppEssentials
import NEHTTPMitM
import XCTest

@testable import NEApp

final class ProfileTests: XCTestCase {

  let profile = Profile(
    basicSettings: BasicSettings(
      logLevel: .trace,
      dnsServers: ["8.8.8.8", "192.168.0.1"],
      exceptions: ["127.0.0.1"],
      httpListenAddress: "127.0.0.1",
      httpListenPort: 6152,
      socksListenAddress: "127.0.0.1",
      socksListenPort: 6153,
      excludeSimpleHostnames: true
    ),
    routingRules: [
      FinalRule("FINAL,PROXY")!,
      DomainRule("DOMAIN,www.example.com,PROXY")!,
      DomainSuffixRule("DOMAIN-SUFFIX,ad.com,BLOCK")!,
    ].map(AnyRoutingRuleRepresentation.init(_:)),
    manInTheMiddleSettings: ManInTheMiddleSettings(
      skipCertificateVerification: true,
      hostnames: ["*.example.com"],
      base64EncodedP12String:
        "MIIKPwIBAzCCCgYGCSqGSIb3DQEHAaCCCfc",
      passphrase: "CS2UNBDR"
    ),
    policies: [
      DirectPolicy(),
      RejectPolicy(),
      RejectTinyGifPolicy(),
      ProxyPolicy(
        name: "HTTP",
        proxy: Proxy(
          serverAddress: "192.168.1.2",
          port: 6152,
          protocol: .http
        )
      ),
      ProxyPolicy(
        name: "SOCKS5",
        proxy: Proxy(
          serverAddress: "192.168.1.2",
          port: 6153,
          protocol: .socks5,
          username: "socks",
          passwordReference: "RldkIdlSo",
          authenticationRequired: true,
          overTls: false
        )
      ),
    ].map(AnyConnectionPolicyRepresentation.init(_:)),
    policyGroups: [
      ManuallySelectedPolicyGroup(name: "PROXY", policies: ["DIRECT", "HTTP"]),
      ManuallySelectedPolicyGroup(name: "BLOCK", policies: ["DIRECT", "REJECT", "REJECT-TINYGIF"]),
    ].map(AnyConnectionPolicyGroupRepresentation.init(_:))
  )

  func testDecodeProfileFromJson() throws {
    let profileString =
      "{\"basicSettings\":{\"dnsServers\":[\"8.8.8.8\",\"192.168.0.1\"],\"exceptions\":[\"127.0.0.1\"],\"excludeSimpleHostnames\":true,\"httpListenAddress\":\"127.0.0.1\",\"httpListenPort\":6152,\"logLevel\":\"trace\",\"socksListenAddress\":\"127.0.0.1\",\"socksListenPort\":6153},\"manInTheMiddleSettings\":{\"base64EncodedP12String\":\"MIIKPwIBAzCCCgYGCSqGSIb3DQEHAaCCCfc\",\"hostnames\":[\"*.example.com\"],\"passphrase\":\"CS2UNBDR\",\"skipCertificateVerification\":true},\"policies\":[{\"name\":\"HTTP\",\"proxy\":{\"port\":6152,\"protocol\":\"http\",\"serverAddress\":\"192.168.1.2\"},\"type\":\"http\"},{\"name\":\"SOCKS5\",\"proxy\":{\"authenticationRequired\":true,\"password\":\"RldkIdlSo\",\"port\":6153,\"protocol\":\"socks5\",\"serverAddress\":\"192.168.1.2\",\"username\":\"socks\"},\"type\":\"socks5\"}],\"policyGroups\":[{\"name\":\"PROXY\",\"policies\":[\"DIRECT\",\"HTTP\"],\"type\":\"select\"},{\"name\":\"BLOCK\",\"policies\":[\"DIRECT\",\"REJECT\",\"REJECT-TINYGIF\"],\"type\":\"select\"}],\"routingRules\":[\"FINAL,PROXY\",\"DOMAIN,www.example.com,PROXY\",\"DOMAIN-SUFFIX,ad.com,BLOCK\"]}"

    let profile = try JSONDecoder().decode(
      Profile.self,
      from: profileString.data(using: .utf8)!
    )

    XCTAssertEqual(profile.basicSettings, self.profile.basicSettings)
    XCTAssertEqual(profile.manInTheMiddleSettings, self.profile.manInTheMiddleSettings)
    XCTAssertEqual(profile.routingRules.count, 3)
    XCTAssertEqual(profile.policies.count, 5)
    XCTAssertEqual(profile.policyGroups.count, 2)
  }

  func testDecodeProfileFromJsonThatDoesNotContainsBasicSettings() throws {
    let profileString =
      "{\"manInTheMiddleSettings\":{\"base64EncodedP12String\":\"MIIKPwIBAzCCCgYGCSqGSIb3DQEHAaCCCfc\",\"hostnames\":[\"*.example.com\"],\"passphrase\":\"CS2UNBDR\",\"skipCertificateVerification\":true},\"policies\":[{\"name\":\"HTTP\",\"proxy\":{\"port\":6152,\"protocol\":\"http\",\"serverAddress\":\"192.168.1.2\"},\"type\":\"http\"},{\"name\":\"SOCKS5\",\"proxy\":{\"authenticationRequired\":true,\"password\":\"RldkIdlSo\",\"port\":6153,\"protocol\":\"socks5\",\"serverAddress\":\"192.168.1.2\",\"username\":\"socks\"},\"type\":\"socks5\"}],\"policyGroups\":[{\"name\":\"PROXY\",\"policies\":[\"DIRECT\",\"HTTP\"],\"type\":\"select\"},{\"name\":\"BLOCK\",\"policies\":[\"DIRECT\",\"REJECT\",\"REJECT-TINYGIF\"],\"type\":\"select\"}],\"routingRules\":[\"FINAL,PROXY\",\"DOMAIN,www.example.com,PROXY\",\"DOMAIN-SUFFIX,ad.com,BLOCK\"]}"

    let profile = try JSONDecoder().decode(
      Profile.self,
      from: profileString.data(using: .utf8)!
    )

    let expectedBasicSettings = BasicSettings()

    XCTAssertEqual(profile.basicSettings, expectedBasicSettings)
    XCTAssertEqual(profile.manInTheMiddleSettings, self.profile.manInTheMiddleSettings)
    XCTAssertEqual(profile.routingRules.count, 3)
    XCTAssertEqual(profile.policies.count, 5)
    XCTAssertEqual(profile.policyGroups.count, 2)
  }

  func testDecodeProfileFromJsonThatDoesNotContainsRules() throws {
    let profileString =
      "{\"basicSettings\":{\"dnsServers\":[\"8.8.8.8\",\"192.168.0.1\"],\"exceptions\":[\"127.0.0.1\"],\"excludeSimpleHostnames\":true,\"httpListenAddress\":\"127.0.0.1\",\"httpListenPort\":6152,\"logLevel\":\"trace\",\"socksListenAddress\":\"127.0.0.1\",\"socksListenPort\":6153},\"manInTheMiddleSettings\":{\"base64EncodedP12String\":\"MIIKPwIBAzCCCgYGCSqGSIb3DQEHAaCCCfc\",\"hostnames\":[\"*.example.com\"],\"passphrase\":\"CS2UNBDR\",\"skipCertificateVerification\":true},\"policies\":[{\"name\":\"HTTP\",\"proxy\":{\"port\":6152,\"protocol\":\"http\",\"serverAddress\":\"192.168.1.2\"},\"type\":\"http\"},{\"name\":\"SOCKS5\",\"proxy\":{\"authenticationRequired\":true,\"password\":\"RldkIdlSo\",\"port\":6153,\"protocol\":\"socks5\",\"serverAddress\":\"192.168.1.2\",\"username\":\"socks\"},\"type\":\"socks5\"}],\"policyGroups\":[{\"name\":\"PROXY\",\"policies\":[\"DIRECT\",\"HTTP\"],\"type\":\"select\"},{\"name\":\"BLOCK\",\"policies\":[\"DIRECT\",\"REJECT\",\"REJECT-TINYGIF\"],\"type\":\"select\"}]}"

    let profile = try JSONDecoder().decode(
      Profile.self,
      from: profileString.data(using: .utf8)!
    )

    XCTAssertEqual(profile.basicSettings, self.profile.basicSettings)
    XCTAssertEqual(profile.manInTheMiddleSettings, self.profile.manInTheMiddleSettings)
    XCTAssertEqual(profile.routingRules.count, 0)
    XCTAssertEqual(profile.policies.count, 5)
    XCTAssertEqual(profile.policyGroups.count, 2)
  }

  func testDecodeProfileFromJsonThatContainsUnknownedRule() throws {
    let profileString =
      "{\"basicSettings\":{\"dnsServers\":[\"8.8.8.8\",\"192.168.0.1\"],\"exceptions\":[\"127.0.0.1\"],\"excludeSimpleHostnames\":true,\"httpListenAddress\":\"127.0.0.1\",\"httpListenPort\":6152,\"logLevel\":\"trace\",\"socksListenAddress\":\"127.0.0.1\",\"socksListenPort\":6153},\"manInTheMiddleSettings\":{\"base64EncodedP12String\":\"MIIKPwIBAzCCCgYGCSqGSIb3DQEHAaCCCfc\",\"hostnames\":[\"*.example.com\"],\"passphrase\":\"CS2UNBDR\",\"skipCertificateVerification\":true},\"policies\":[{\"name\":\"HTTP\",\"proxy\":{\"port\":6152,\"protocol\":\"http\",\"serverAddress\":\"192.168.1.2\"},\"type\":\"http\"},{\"name\":\"SOCKS5\",\"proxy\":{\"authenticationRequired\":true,\"password\":\"RldkIdlSo\",\"port\":6153,\"protocol\":\"socks5\",\"serverAddress\":\"192.168.1.2\",\"username\":\"socks\"},\"type\":\"socks5\"}],\"policyGroups\":[{\"name\":\"PROXY\",\"policies\":[\"DIRECT\",\"HTTP\"],\"type\":\"select\"},{\"name\":\"BLOCK\",\"policies\":[\"DIRECT\",\"REJECT\",\"REJECT-TINYGIF\"],\"type\":\"select\"}],\"routingRules\":[\"FINAL,PROXY\",\"DOMAIN,www.example.com,PROXY\",\"DOMAIN-SUFFIX,ad.com,BLOCK\"]}"

    XCTAssertNoThrow(
      try JSONDecoder().decode(Profile.self, from: profileString.data(using: .utf8)!)
    )
  }

  func testDecodeProfileFromJsonThatDoesNotContainsPolicies() throws {
    let profileString =
      "{\"basicSettings\":{\"dnsServers\":[\"8.8.8.8\",\"192.168.0.1\"],\"exceptions\":[\"127.0.0.1\"],\"excludeSimpleHostnames\":true,\"httpListenAddress\":\"127.0.0.1\",\"httpListenPort\":6152,\"logLevel\":\"trace\",\"socksListenAddress\":\"127.0.0.1\",\"socksListenPort\":6153},\"manInTheMiddleSettings\":{\"base64EncodedP12String\":\"MIIKPwIBAzCCCgYGCSqGSIb3DQEHAaCCCfc\",\"hostnames\":[\"*.example.com\"],\"passphrase\":\"CS2UNBDR\",\"skipCertificateVerification\":true},\"policyGroups\":[{\"name\":\"PROXY\",\"policies\":[\"DIRECT\"],\"type\":\"select\"},{\"name\":\"BLOCK\",\"policies\":[\"DIRECT\",\"REJECT\",\"REJECT-TINYGIF\"],\"type\":\"select\"}],\"routingRules\":[\"FINAL,PROXY\",\"DOMAIN,www.example.com,PROXY\",\"DOMAIN-SUFFIX,ad.com,BLOCK\"]}"

    let profile = try JSONDecoder().decode(
      Profile.self,
      from: profileString.data(using: .utf8)!
    )

    XCTAssertEqual(profile.basicSettings, self.profile.basicSettings)
    XCTAssertEqual(profile.manInTheMiddleSettings, self.profile.manInTheMiddleSettings)
    XCTAssertEqual(profile.routingRules.count, 3)
    XCTAssertEqual(profile.policies.count, 3)
    XCTAssertEqual(profile.policyGroups.count, 2)
  }

  func testDecodeProfileFromJsonThatDoesNotContainsPolicyGroups() throws {
    let profileString =
      "{\"basicSettings\":{\"dnsServers\":[\"8.8.8.8\",\"192.168.0.1\"],\"exceptions\":[\"127.0.0.1\"],\"excludeSimpleHostnames\":true,\"httpListenAddress\":\"127.0.0.1\",\"httpListenPort\":6152,\"logLevel\":\"trace\",\"socksListenAddress\":\"127.0.0.1\",\"socksListenPort\":6153},\"manInTheMiddleSettings\":{\"base64EncodedP12String\":\"MIIKPwIBAzCCCgYGCSqGSIb3DQEHAaCCCfc\",\"hostnames\":[\"*.example.com\"],\"passphrase\":\"CS2UNBDR\",\"skipCertificateVerification\":true},\"policies\":[{\"name\":\"HTTP\",\"proxy\":{\"port\":6152,\"protocol\":\"http\",\"serverAddress\":\"192.168.1.2\"},\"type\":\"http\"},{\"name\":\"SOCKS5\",\"proxy\":{\"authenticationRequired\":true,\"password\":\"RldkIdlSo\",\"port\":6153,\"protocol\":\"socks5\",\"serverAddress\":\"192.168.1.2\",\"username\":\"socks\"},\"type\":\"socks5\"}],\"routingRules\":[\"FINAL,SOCKS5\",\"DOMAIN,www.example.com,HTTP\",\"DOMAIN-SUFFIX,ad.com,REJECT\"]}"

    let profile = try JSONDecoder().decode(
      Profile.self,
      from: profileString.data(using: .utf8)!
    )

    XCTAssertEqual(profile.basicSettings, self.profile.basicSettings)
    XCTAssertEqual(profile.manInTheMiddleSettings, self.profile.manInTheMiddleSettings)
    XCTAssertEqual(profile.routingRules.count, 3)
    XCTAssertEqual(profile.policies.count, 5)
    XCTAssertEqual(profile.policyGroups.count, 0)
  }

  func testDecodeProfileFromJsonThatDoesNotContainsManInTheMiddleSettings() throws {
    let profileString =
      "{\"basicSettings\":{\"dnsServers\":[\"8.8.8.8\",\"192.168.0.1\"],\"exceptions\":[\"127.0.0.1\"],\"excludeSimpleHostnames\":true,\"httpListenAddress\":\"127.0.0.1\",\"httpListenPort\":6152,\"logLevel\":\"trace\",\"socksListenAddress\":\"127.0.0.1\",\"socksListenPort\":6153},\"policies\":[{\"name\":\"HTTP\",\"proxy\":{\"port\":6152,\"protocol\":\"http\",\"serverAddress\":\"192.168.1.2\"},\"type\":\"http\"},{\"name\":\"SOCKS5\",\"proxy\":{\"authenticationRequired\":true,\"password\":\"RldkIdlSo\",\"port\":6153,\"protocol\":\"socks5\",\"serverAddress\":\"192.168.1.2\",\"username\":\"socks\"},\"type\":\"socks5\"}],\"policyGroups\":[{\"name\":\"PROXY\",\"policies\":[\"DIRECT\",\"HTTP\"],\"type\":\"select\"},{\"name\":\"BLOCK\",\"policies\":[\"DIRECT\",\"REJECT\",\"REJECT-TINYGIF\"],\"type\":\"select\"}],\"routingRules\":[\"FINAL,PROXY\",\"DOMAIN,www.example.com,PROXY\",\"DOMAIN-SUFFIX,ad.com,BLOCK\"]}"

    let profile = try JSONDecoder().decode(
      Profile.self,
      from: profileString.data(using: .utf8)!
    )

    let expectedManInTheMiddleSettings = ManInTheMiddleSettings()

    XCTAssertEqual(profile.basicSettings, self.profile.basicSettings)
    XCTAssertEqual(profile.manInTheMiddleSettings, expectedManInTheMiddleSettings)
    XCTAssertEqual(profile.routingRules.count, 3)
    XCTAssertEqual(profile.policies.count, 5)
    XCTAssertEqual(profile.policyGroups.count, 2)
  }

  func testDecodeProfileFromEmptyJsonObject() throws {
    let profileString = "{}"

    let profile = try JSONDecoder().decode(
      Profile.self,
      from: profileString.data(using: .utf8)!
    )

    XCTAssertEqual(profile.basicSettings, .init())
    XCTAssertEqual(profile.manInTheMiddleSettings, .init())
    XCTAssertEqual(profile.policies.count, 3)
    XCTAssertTrue(profile.policyGroups.isEmpty)
  }

  func testEncodeProfileToJson() throws {
    let expectedProfileString =
      "{\"basicSettings\":{\"dnsServers\":[\"8.8.8.8\",\"192.168.0.1\"],\"exceptions\":[\"127.0.0.1\"],\"excludeSimpleHostnames\":true,\"httpListenAddress\":\"127.0.0.1\",\"httpListenPort\":6152,\"logLevel\":\"trace\",\"socksListenAddress\":\"127.0.0.1\",\"socksListenPort\":6153},\"manInTheMiddleSettings\":{\"base64EncodedP12String\":\"MIIKPwIBAzCCCgYGCSqGSIb3DQEHAaCCCfc\",\"hostnames\":[\"*.example.com\"],\"passphrase\":\"CS2UNBDR\",\"skipCertificateVerification\":true},\"policies\":[{\"name\":\"DIRECT\",\"type\":\"direct\"},{\"name\":\"REJECT\",\"type\":\"reject\"},{\"name\":\"REJECT-TINYGIF\",\"type\":\"reject-tinygif\"},{\"name\":\"HTTP\",\"proxy\":{\"port\":6152,\"protocol\":\"http\",\"serverAddress\":\"192.168.1.2\"},\"type\":\"http\"},{\"name\":\"SOCKS5\",\"proxy\":{\"authenticationRequired\":true,\"passwordReference\":\"RldkIdlSo\",\"port\":6153,\"protocol\":\"socks5\",\"serverAddress\":\"192.168.1.2\",\"username\":\"socks\"},\"type\":\"socks5\"}],\"policyGroups\":[{\"name\":\"PROXY\",\"policies\":[\"DIRECT\",\"HTTP\"],\"type\":\"select\"},{\"name\":\"BLOCK\",\"policies\":[\"DIRECT\",\"REJECT\",\"REJECT-TINYGIF\"],\"type\":\"select\"}],\"routingRules\":[\"FINAL,PROXY\",\"DOMAIN,www.example.com,PROXY\",\"DOMAIN-SUFFIX,ad.com,BLOCK\"]}"

    let encoder = JSONEncoder()
    encoder.outputFormatting = .sortedKeys

    let profileString = String(data: try encoder.encode(profile), encoding: .utf8)

    XCTAssertEqual(profileString, expectedProfileString)
  }

  func testEncodeProfileContainingMostlyDefaultValue() throws {
    let expectedProfileString =
      "{\"basicSettings\":{\"dnsServers\":[],\"exceptions\":[],\"excludeSimpleHostnames\":false,\"logLevel\":\"info\"},\"manInTheMiddleSettings\":{\"hostnames\":[],\"skipCertificateVerification\":false},\"policies\":[],\"policyGroups\":[],\"routingRules\":[]}"

    let profile = Profile(
      basicSettings: BasicSettings(),
      routingRules: [],
      manInTheMiddleSettings: ManInTheMiddleSettings(),
      policies: [],
      policyGroups: []
    )

    let encoder = JSONEncoder()
    encoder.outputFormatting = .sortedKeys

    let profileString = String(data: try encoder.encode(profile), encoding: .utf8)

    XCTAssertEqual(profileString, expectedProfileString)
  }

  func testEncodeProfileContainingDefaultBasicSettings() throws {
    let expectedProfileString =
      "{\"basicSettings\":{\"dnsServers\":[],\"exceptions\":[],\"excludeSimpleHostnames\":false,\"logLevel\":\"info\"},\"manInTheMiddleSettings\":{\"base64EncodedP12String\":\"MIIKPwIBAzCCCgYGCSqGSIb3DQEHAaCCCfc\",\"hostnames\":[\"*.example.com\"],\"passphrase\":\"CS2UNBDR\",\"skipCertificateVerification\":true},\"policies\":[{\"name\":\"DIRECT\",\"type\":\"direct\"},{\"name\":\"REJECT\",\"type\":\"reject\"},{\"name\":\"REJECT-TINYGIF\",\"type\":\"reject-tinygif\"},{\"name\":\"HTTP\",\"proxy\":{\"port\":6152,\"protocol\":\"http\",\"serverAddress\":\"192.168.1.2\"},\"type\":\"http\"},{\"name\":\"SOCKS5\",\"proxy\":{\"authenticationRequired\":true,\"passwordReference\":\"RldkIdlSo\",\"port\":6153,\"protocol\":\"socks5\",\"serverAddress\":\"192.168.1.2\",\"username\":\"socks\"},\"type\":\"socks5\"}],\"policyGroups\":[{\"name\":\"PROXY\",\"policies\":[\"DIRECT\",\"HTTP\"],\"type\":\"select\"},{\"name\":\"BLOCK\",\"policies\":[\"DIRECT\",\"REJECT\",\"REJECT-TINYGIF\"],\"type\":\"select\"}],\"routingRules\":[\"FINAL,PROXY\",\"DOMAIN,www.example.com,PROXY\",\"DOMAIN-SUFFIX,ad.com,BLOCK\"]}"

    let encoder = JSONEncoder()
    encoder.outputFormatting = .sortedKeys

    var profile = self.profile
    profile.basicSettings = .init()

    let profileString = String(data: try encoder.encode(profile), encoding: .utf8)

    XCTAssertEqual(profileString, expectedProfileString)
  }

  func testEncodeProfileWhichRulesIsEmpty() throws {
    let expectedProfileString =
      "{\"basicSettings\":{\"dnsServers\":[\"8.8.8.8\",\"192.168.0.1\"],\"exceptions\":[\"127.0.0.1\"],\"excludeSimpleHostnames\":true,\"httpListenAddress\":\"127.0.0.1\",\"httpListenPort\":6152,\"logLevel\":\"trace\",\"socksListenAddress\":\"127.0.0.1\",\"socksListenPort\":6153},\"manInTheMiddleSettings\":{\"base64EncodedP12String\":\"MIIKPwIBAzCCCgYGCSqGSIb3DQEHAaCCCfc\",\"hostnames\":[\"*.example.com\"],\"passphrase\":\"CS2UNBDR\",\"skipCertificateVerification\":true},\"policies\":[{\"name\":\"DIRECT\",\"type\":\"direct\"},{\"name\":\"REJECT\",\"type\":\"reject\"},{\"name\":\"REJECT-TINYGIF\",\"type\":\"reject-tinygif\"},{\"name\":\"HTTP\",\"proxy\":{\"port\":6152,\"protocol\":\"http\",\"serverAddress\":\"192.168.1.2\"},\"type\":\"http\"},{\"name\":\"SOCKS5\",\"proxy\":{\"authenticationRequired\":true,\"passwordReference\":\"RldkIdlSo\",\"port\":6153,\"protocol\":\"socks5\",\"serverAddress\":\"192.168.1.2\",\"username\":\"socks\"},\"type\":\"socks5\"}],\"policyGroups\":[{\"name\":\"PROXY\",\"policies\":[\"DIRECT\",\"HTTP\"],\"type\":\"select\"},{\"name\":\"BLOCK\",\"policies\":[\"DIRECT\",\"REJECT\",\"REJECT-TINYGIF\"],\"type\":\"select\"}],\"routingRules\":[]}"

    var profile = self.profile
    profile.routingRules = []

    let encoder = JSONEncoder()
    encoder.outputFormatting = .sortedKeys

    let profileString = String(data: try encoder.encode(profile), encoding: .utf8)

    XCTAssertEqual(profileString, expectedProfileString)
  }

  func testEncodeProfileWhichPoliciesIsEmpty() throws {
    let expectedProfileString =
      "{\"basicSettings\":{\"dnsServers\":[\"8.8.8.8\",\"192.168.0.1\"],\"exceptions\":[\"127.0.0.1\"],\"excludeSimpleHostnames\":true,\"httpListenAddress\":\"127.0.0.1\",\"httpListenPort\":6152,\"logLevel\":\"trace\",\"socksListenAddress\":\"127.0.0.1\",\"socksListenPort\":6153},\"manInTheMiddleSettings\":{\"base64EncodedP12String\":\"MIIKPwIBAzCCCgYGCSqGSIb3DQEHAaCCCfc\",\"hostnames\":[\"*.example.com\"],\"passphrase\":\"CS2UNBDR\",\"skipCertificateVerification\":true},\"policies\":[],\"policyGroups\":[{\"name\":\"PROXY\",\"policies\":[\"DIRECT\",\"HTTP\"],\"type\":\"select\"},{\"name\":\"BLOCK\",\"policies\":[\"DIRECT\",\"REJECT\",\"REJECT-TINYGIF\"],\"type\":\"select\"}],\"routingRules\":[\"FINAL,PROXY\",\"DOMAIN,www.example.com,PROXY\",\"DOMAIN-SUFFIX,ad.com,BLOCK\"]}"

    var profile = self.profile
    profile.policies = []

    let encoder = JSONEncoder()
    encoder.outputFormatting = .sortedKeys

    let profileString = String(data: try encoder.encode(profile), encoding: .utf8)

    XCTAssertEqual(profileString, expectedProfileString)
  }

  func testEncodeProfileWhichPolicyGroupIsEmpty() throws {
    let expectedProfileString =
      "{\"basicSettings\":{\"dnsServers\":[\"8.8.8.8\",\"192.168.0.1\"],\"exceptions\":[\"127.0.0.1\"],\"excludeSimpleHostnames\":true,\"httpListenAddress\":\"127.0.0.1\",\"httpListenPort\":6152,\"logLevel\":\"trace\",\"socksListenAddress\":\"127.0.0.1\",\"socksListenPort\":6153},\"manInTheMiddleSettings\":{\"base64EncodedP12String\":\"MIIKPwIBAzCCCgYGCSqGSIb3DQEHAaCCCfc\",\"hostnames\":[\"*.example.com\"],\"passphrase\":\"CS2UNBDR\",\"skipCertificateVerification\":true},\"policies\":[{\"name\":\"DIRECT\",\"type\":\"direct\"},{\"name\":\"REJECT\",\"type\":\"reject\"},{\"name\":\"REJECT-TINYGIF\",\"type\":\"reject-tinygif\"},{\"name\":\"HTTP\",\"proxy\":{\"port\":6152,\"protocol\":\"http\",\"serverAddress\":\"192.168.1.2\"},\"type\":\"http\"},{\"name\":\"SOCKS5\",\"proxy\":{\"authenticationRequired\":true,\"passwordReference\":\"RldkIdlSo\",\"port\":6153,\"protocol\":\"socks5\",\"serverAddress\":\"192.168.1.2\",\"username\":\"socks\"},\"type\":\"socks5\"}],\"policyGroups\":[],\"routingRules\":[\"FINAL,PROXY\",\"DOMAIN,www.example.com,PROXY\",\"DOMAIN-SUFFIX,ad.com,BLOCK\"]}"

    var profile = self.profile
    profile.policyGroups = []

    let encoder = JSONEncoder()
    encoder.outputFormatting = .sortedKeys

    let profileString = String(data: try encoder.encode(profile), encoding: .utf8)

    XCTAssertEqual(profileString, expectedProfileString)
  }

  func testEncodeProfileContainingDefaultManInTheMiddleSettings() throws {
    let expectedProfileString =
      "{\"basicSettings\":{\"dnsServers\":[\"8.8.8.8\",\"192.168.0.1\"],\"exceptions\":[\"127.0.0.1\"],\"excludeSimpleHostnames\":true,\"httpListenAddress\":\"127.0.0.1\",\"httpListenPort\":6152,\"logLevel\":\"trace\",\"socksListenAddress\":\"127.0.0.1\",\"socksListenPort\":6153},\"manInTheMiddleSettings\":{\"hostnames\":[],\"skipCertificateVerification\":false},\"policies\":[{\"name\":\"DIRECT\",\"type\":\"direct\"},{\"name\":\"REJECT\",\"type\":\"reject\"},{\"name\":\"REJECT-TINYGIF\",\"type\":\"reject-tinygif\"},{\"name\":\"HTTP\",\"proxy\":{\"port\":6152,\"protocol\":\"http\",\"serverAddress\":\"192.168.1.2\"},\"type\":\"http\"},{\"name\":\"SOCKS5\",\"proxy\":{\"authenticationRequired\":true,\"passwordReference\":\"RldkIdlSo\",\"port\":6153,\"protocol\":\"socks5\",\"serverAddress\":\"192.168.1.2\",\"username\":\"socks\"},\"type\":\"socks5\"}],\"policyGroups\":[{\"name\":\"PROXY\",\"policies\":[\"DIRECT\",\"HTTP\"],\"type\":\"select\"},{\"name\":\"BLOCK\",\"policies\":[\"DIRECT\",\"REJECT\",\"REJECT-TINYGIF\"],\"type\":\"select\"}],\"routingRules\":[\"FINAL,PROXY\",\"DOMAIN,www.example.com,PROXY\",\"DOMAIN-SUFFIX,ad.com,BLOCK\"]}"

    var profile = self.profile
    profile.manInTheMiddleSettings = .init()

    let encoder = JSONEncoder()
    encoder.outputFormatting = .sortedKeys

    let profileString = String(data: try encoder.encode(profile), encoding: .utf8)

    XCTAssertEqual(profileString, expectedProfileString)
  }
}
