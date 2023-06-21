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
      "{\"policies\":[{\"name\":\"HTTP\",\"proxy\":{\"port\":8310,\"protocol\":\"http\",\"serverAddress\":\"127.0.0.1\"},\"type\":\"http\"}],\"policyGroups\":[{\"name\":\"BLOCK\",\"policies\":[\"DIRECT\",\"REJECT\",\"REJECT-TINYGIF\"],\"type\":\"select\"},{\"name\":\"PROXY\",\"policies\":[\"HTTP\"],\"type\":\"select\"}],\"rules\":[\"DOMAIN-SUFFIX,example.com,DIRECT\",\"RULE-SET,SYSTEM,DIRECT\",\"GEOIP,CN,DIRECT\",\"FINAL,PROXY\"]}"

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
      "{\"policies\":[{\"name\":\"HTTP\",\"proxy\":{\"port\":8310,\"protocol\":\"http\",\"serverAddress\":\"127.0.0.1\"},\"type\":\"http\"}],\"rules\":[\"DOMAIN-SUFFIX,example.com,DIRECT\",\"RULE-SET,SYSTEM,DIRECT\",\"GEOIP,CN,DIRECT\",\"FINAL,HTTP\"]}"

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
      "{\"policies\":[{\"name\":\"HTTP\",\"proxy\":{\"port\":8310,\"protocol\":\"http\",\"serverAddress\":\"127.0.0.1\"},\"type\":\"http\"}],\"policyGroups\":[{\"name\":\"PROXY\",\"policies\":[\"HTTP\"],\"type\":\"select\"}],\"rules\":[\"DOMAIN-SUFFIX,example.com,PROXY\",\"RULE-SET,SYSTEM,PROXY\",\"GEOIP,CN,PROXY\",\"FINAL,PROXY\"]}"

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
      "{\"manInTheMiddleSettings\":{\"base64EncodedP12String\":\"MIIKPwIBAzCCCgYGCSqGSIb3DQEHAaCCCfcEggnzMIIJ7zCCBGcGCSqGSIb3DQEHBqCCBFgwggRUAgEAMIIETQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYwDgQIMS\\/Omaol11sCAggAgIIEICIvmL+gZSFA+2e1GDIu19M1uYopcuPCGPCaZbXoQ87P6xf\\/\\/qIiuZ9tBaVbdLm7CFUeTnBH725SXSdYdwXeLAcjydfiWqcDoSTVpDiXe+S37R2UnEeg5yZFzM2hjRpLet+P5S+wiIRC2XjZgCK0Em7id0D50AeepTFGeN0TukY\\/HqZj+aG\\/OnCNNo8AnQ\\/P1yCc+ytTTcqKVJt3u1bABpRPQaf\\/fYEOBAZSGr\\/vGz21COGrHAlYinT+rYi43nuIVTQZdmSKeXFfaLPJsIl9rn8Yz9eQ9jT5ErjPUPfucjEHrG9Da5X9aD1j8RYXd9Y440EIwp4PoATz71CCkZEQ++FL992JF95Qy9sSpGFkeU3VIbv0vXQvcqQf0jAwVSERWbjB5A+LiHDUqYC0d\\/cxWr37a0iKXcPgTvrwiSSlgW7iiwLsdQgEwinBItTR1K+jPpNWkHyoJ81oU2GCM0qcGoDXpIgqKJhhG4TxiIp1qy8J5W6HPwRIPkAVLVBeQBg2Mhj\\/keaNqXCTC2I50OuAuPncM15N61+TMXFhVBxsarJrG3Dcb0laf\\/MafVarne8\\/8ADrf2F6I\\/R0uavQqjgxmTcIbrLyXP7iZAaksOHSsECG4jw7dOcA3osO6sH+yRul5bqJdUrqDf1u2vtjtCvCJGhfwzwlH79ifKtofkaq59rR0d0LzwJ4QfhgttE2ax43J4sQ8VIHEmMJW1HrzvOsPRBUNFVuZJPKunFKePtoGpH3SMW8qSPNzaHE+\\/yhNZQV0aO55XugfuPoJstEsrRsUj1u31gCXNHgO5cVs4nwzP0iilmssWQIVT0KTi9IDHcK+8tttOAF3B56hs\\/EDHNLecF6m1ENnbhtIlt\\/mULZ6jrJcRrWsW1VULXXcRmZ+kIEm9y0d5vtHf+M2AO+pcwAkhMGVUPOrfv0Oq1n4+JiHeoP7m1oj71FklaHksBoOpoLsZ0wTW2lAmXh4II\\/If6kj5XaZNdggYbvwLcEQBIvzk012q\\/rLnCoLojzjHMPd7fSRgZ3LjblkS\\/Z8vyAqrJE3Tl9oV+mqbGgkxH9WG0IsbCahHP3XSVUdNm5RD3vdDtXEgtjPZtTef+qKDeCHTHpzF9W4nlZjCWZ6hLgC8UnWgqMTVSJI4QOgIoRNpXf6XFc9JUSEFEouyq5v4LykWKS43NKV4pTS\\/NY6LR9GdoaOWC8Ykpj6ZPtAbTUvb0iRSa6hwf4Yhc5msAks8LWgnVUQMbO3wxkuDa6MJf\\/HuoHxhd0y5FBL47nd49tWFg4+DXzH64\\/gWXWMPhhOB1zmmXcg3q9kO15dR7h4XCxOnoYgCEaPNFrYc3ed1dKqU6RH20lhbwUCykTJDkFdc21q0LYuGfpU4ov3AJvR1yeKgh2WyBJ7prNVnF2k4IUBB+bA5XCYDCCBYAGCSqGSIb3DQEHAaCCBXEEggVtMIIFaTCCBWUGCyqGSIb3DQEMCgECoIIE7jCCBOowHAYKKoZIhvcNAQwBAzAOBAj+Bzy35X5qfgICCAAEggTI9GLmCbW9dpbESlxX7VHBcWXV5PpVFif79q8UTpbMO3SVEJ6DD8jdgfYCRRCQTe7Ovs4m4ySdlJC3XmYnv+h4dihjuY2ZTJ+nt89GQTurEXomVgeR22I1KiCO29\\/ZYxJGsAqnDKnl0RM0F+2Te9kiSSEfgaFWLYR+8h8mgy6q8wyDTecWRqyJQ4Rm+aHTyKVF8pMQh3R6lQJpG\\/s14t1qhUv2rK+WAJfruSvbv2ZXtRZJ4xuI7LIYzT00vrd2s9whH0znTcGTrL9seiOaZVG0bIR8o\\/Roat6Yigh+oQxdERYNdRbTD2g4akLolve\\/8mgwUpG3XHRKdIQkcclUoCJKB4Bjjxo9kRtdTvUx+fCASmLtXSNin7NMEMeydrSfe\\/tYUYtBHarzdKC5Cu6xzRbOe6zByKSv7xk6xOtYG0kc6Gy+DlvQNW1C+s+qEHZ\\/V26VwVskQpUnSkw3jR4JEIJICcanw0pqqtdqKuzwhuvWihwGCiRkVIqqJmODEHAZThTaeDo07kc0JPq7hsK9zenVvirAlyaBdF8EmRfAgx4Q8\\/jRdyIHONKNohvYNsbzscTHlOpqZNTdIPbmlxSiCoLpkWd4Fdc9oQ4ta1x41PMd877m0O+KquwxGqwj4emJQLZmMyDn1obr9pAXDFyXJFDusoRPqVB+4x2Ie34Des1FnI00FjVI2HAwM29doaqYuR6yqtkCuxDZ2rLDnrdsTzK\\/7HtuhmjCc6+ZTbbIRK1Y34ojSRwJgFIskGevAjvwRZtbq4GOd3aJXrFAvYNE\\/2RlGBl3oqvap89SLzZsY1k7xSPiJal0DV5im82tAyc23HcRjsG6B9uEDkQb\\/i7+9wqXxhLlJfs\\/et7SXhKmjPNEoUu3tdAwiPvhYg2kIaeyeBdPFpBS6km1th61cjCYX2gpnTtLOb9oBqf\\/GyRQVLhpH9x8pIvjPO2LHTio0XbKT3NYDXzr9SnGm+IX4PwQvWaOwBNYWXj0h4NMHimUA0urtvsrC9DWBIjeybKJAvC6CUs1oWbGfazbBSSKejpeg+Q6mKhac+0PTg2\\/0JQC9LfAgXc72ed4O7kKbhccWBTwrmqC+VuEkGv5\\/gn+J8D2j0pgwqcDzLy+q17QoymSNr136KJvfx025nx\\/C5CEw4xiD6\\/FBnqCyNCt98RYXp9YNLVPxqcEQ0haSbjhjBv+j9quRbNKqA4Tw7vsEKRV\\/6rfsEp0cxiXCQjZ+sYamx3j8Wnm4aUry3URb3itEaKdsnrZcHI6G4UNDx+AjG68f4cCNkHmjBVbGsREunZnEiEzsXWpsz5piCxT5t0b9XYDOZGotnRwpFIki2DorW4+8w+ItYVLYQaoDPl1K7UoJM5zmtGfH7\\/tfCn1gwJYAnyj2yU544KyhI6HflAKHdADuIVZdHcRSTQ2Cl3qMdIogrQe5d2WG6wRU2Wo\\/jA2j4zANC2s9qKqYxajCwfHfACzisjihxjGwzcgJ1jBm0tC2dQA2IhQg+IqXlbPx2BMc4\\/6jfetmVeKhXpaA0jB9s67kP1JM7mdkLb9A0di8uMcNos1Uv0bGyNYQncbQ8HeV7aGxxg9fBNWPgPCP8kIJKFiEmrZxBfG4YYtf+iN+JrP5Z\\/NvukBooC2+p1+Jq\\/bMWQwIwYJKoZIhvcNAQkVMRYEFMbkckLpQhQd891xl1MJiI4JN\\/DuMD0GCSqGSIb3DQEJFDEwHi4ATgBlAHQAYgBvAHQAIABSAG8AbwB0ACAAQwBBACAAQwBTADIAVQBOAEIARABSMDAwITAJBgUrDgMCGgUABBTv0DZW5WGOyttIiEY23f3RInSpEwQIoXlbDNrNFtcCAQE=\",\"hostnames\":[\"*.example.com\"],\"passphrase\":\"CS2UNBDR\",\"skipCertificateVerification\":true}}"

    let manInTheMiddleSettingsString = """
      [MitM]
      base64-encoded-p12-string = MIIKPwIBAzCCCgYGCSqGSIb3DQEHAaCCCfcEggnzMIIJ7zCCBGcGCSqGSIb3DQEHBqCCBFgwggRUAgEAMIIETQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYwDgQIMS/Omaol11sCAggAgIIEICIvmL+gZSFA+2e1GDIu19M1uYopcuPCGPCaZbXoQ87P6xf//qIiuZ9tBaVbdLm7CFUeTnBH725SXSdYdwXeLAcjydfiWqcDoSTVpDiXe+S37R2UnEeg5yZFzM2hjRpLet+P5S+wiIRC2XjZgCK0Em7id0D50AeepTFGeN0TukY/HqZj+aG/OnCNNo8AnQ/P1yCc+ytTTcqKVJt3u1bABpRPQaf/fYEOBAZSGr/vGz21COGrHAlYinT+rYi43nuIVTQZdmSKeXFfaLPJsIl9rn8Yz9eQ9jT5ErjPUPfucjEHrG9Da5X9aD1j8RYXd9Y440EIwp4PoATz71CCkZEQ++FL992JF95Qy9sSpGFkeU3VIbv0vXQvcqQf0jAwVSERWbjB5A+LiHDUqYC0d/cxWr37a0iKXcPgTvrwiSSlgW7iiwLsdQgEwinBItTR1K+jPpNWkHyoJ81oU2GCM0qcGoDXpIgqKJhhG4TxiIp1qy8J5W6HPwRIPkAVLVBeQBg2Mhj/keaNqXCTC2I50OuAuPncM15N61+TMXFhVBxsarJrG3Dcb0laf/MafVarne8/8ADrf2F6I/R0uavQqjgxmTcIbrLyXP7iZAaksOHSsECG4jw7dOcA3osO6sH+yRul5bqJdUrqDf1u2vtjtCvCJGhfwzwlH79ifKtofkaq59rR0d0LzwJ4QfhgttE2ax43J4sQ8VIHEmMJW1HrzvOsPRBUNFVuZJPKunFKePtoGpH3SMW8qSPNzaHE+/yhNZQV0aO55XugfuPoJstEsrRsUj1u31gCXNHgO5cVs4nwzP0iilmssWQIVT0KTi9IDHcK+8tttOAF3B56hs/EDHNLecF6m1ENnbhtIlt/mULZ6jrJcRrWsW1VULXXcRmZ+kIEm9y0d5vtHf+M2AO+pcwAkhMGVUPOrfv0Oq1n4+JiHeoP7m1oj71FklaHksBoOpoLsZ0wTW2lAmXh4II/If6kj5XaZNdggYbvwLcEQBIvzk012q/rLnCoLojzjHMPd7fSRgZ3LjblkS/Z8vyAqrJE3Tl9oV+mqbGgkxH9WG0IsbCahHP3XSVUdNm5RD3vdDtXEgtjPZtTef+qKDeCHTHpzF9W4nlZjCWZ6hLgC8UnWgqMTVSJI4QOgIoRNpXf6XFc9JUSEFEouyq5v4LykWKS43NKV4pTS/NY6LR9GdoaOWC8Ykpj6ZPtAbTUvb0iRSa6hwf4Yhc5msAks8LWgnVUQMbO3wxkuDa6MJf/HuoHxhd0y5FBL47nd49tWFg4+DXzH64/gWXWMPhhOB1zmmXcg3q9kO15dR7h4XCxOnoYgCEaPNFrYc3ed1dKqU6RH20lhbwUCykTJDkFdc21q0LYuGfpU4ov3AJvR1yeKgh2WyBJ7prNVnF2k4IUBB+bA5XCYDCCBYAGCSqGSIb3DQEHAaCCBXEEggVtMIIFaTCCBWUGCyqGSIb3DQEMCgECoIIE7jCCBOowHAYKKoZIhvcNAQwBAzAOBAj+Bzy35X5qfgICCAAEggTI9GLmCbW9dpbESlxX7VHBcWXV5PpVFif79q8UTpbMO3SVEJ6DD8jdgfYCRRCQTe7Ovs4m4ySdlJC3XmYnv+h4dihjuY2ZTJ+nt89GQTurEXomVgeR22I1KiCO29/ZYxJGsAqnDKnl0RM0F+2Te9kiSSEfgaFWLYR+8h8mgy6q8wyDTecWRqyJQ4Rm+aHTyKVF8pMQh3R6lQJpG/s14t1qhUv2rK+WAJfruSvbv2ZXtRZJ4xuI7LIYzT00vrd2s9whH0znTcGTrL9seiOaZVG0bIR8o/Roat6Yigh+oQxdERYNdRbTD2g4akLolve/8mgwUpG3XHRKdIQkcclUoCJKB4Bjjxo9kRtdTvUx+fCASmLtXSNin7NMEMeydrSfe/tYUYtBHarzdKC5Cu6xzRbOe6zByKSv7xk6xOtYG0kc6Gy+DlvQNW1C+s+qEHZ/V26VwVskQpUnSkw3jR4JEIJICcanw0pqqtdqKuzwhuvWihwGCiRkVIqqJmODEHAZThTaeDo07kc0JPq7hsK9zenVvirAlyaBdF8EmRfAgx4Q8/jRdyIHONKNohvYNsbzscTHlOpqZNTdIPbmlxSiCoLpkWd4Fdc9oQ4ta1x41PMd877m0O+KquwxGqwj4emJQLZmMyDn1obr9pAXDFyXJFDusoRPqVB+4x2Ie34Des1FnI00FjVI2HAwM29doaqYuR6yqtkCuxDZ2rLDnrdsTzK/7HtuhmjCc6+ZTbbIRK1Y34ojSRwJgFIskGevAjvwRZtbq4GOd3aJXrFAvYNE/2RlGBl3oqvap89SLzZsY1k7xSPiJal0DV5im82tAyc23HcRjsG6B9uEDkQb/i7+9wqXxhLlJfs/et7SXhKmjPNEoUu3tdAwiPvhYg2kIaeyeBdPFpBS6km1th61cjCYX2gpnTtLOb9oBqf/GyRQVLhpH9x8pIvjPO2LHTio0XbKT3NYDXzr9SnGm+IX4PwQvWaOwBNYWXj0h4NMHimUA0urtvsrC9DWBIjeybKJAvC6CUs1oWbGfazbBSSKejpeg+Q6mKhac+0PTg2/0JQC9LfAgXc72ed4O7kKbhccWBTwrmqC+VuEkGv5/gn+J8D2j0pgwqcDzLy+q17QoymSNr136KJvfx025nx/C5CEw4xiD6/FBnqCyNCt98RYXp9YNLVPxqcEQ0haSbjhjBv+j9quRbNKqA4Tw7vsEKRV/6rfsEp0cxiXCQjZ+sYamx3j8Wnm4aUry3URb3itEaKdsnrZcHI6G4UNDx+AjG68f4cCNkHmjBVbGsREunZnEiEzsXWpsz5piCxT5t0b9XYDOZGotnRwpFIki2DorW4+8w+ItYVLYQaoDPl1K7UoJM5zmtGfH7/tfCn1gwJYAnyj2yU544KyhI6HflAKHdADuIVZdHcRSTQ2Cl3qMdIogrQe5d2WG6wRU2Wo/jA2j4zANC2s9qKqYxajCwfHfACzisjihxjGwzcgJ1jBm0tC2dQA2IhQg+IqXlbPx2BMc4/6jfetmVeKhXpaA0jB9s67kP1JM7mdkLb9A0di8uMcNos1Uv0bGyNYQncbQ8HeV7aGxxg9fBNWPgPCP8kIJKFiEmrZxBfG4YYtf+iN+JrP5Z/NvukBooC2+p1+Jq/bMWQwIwYJKoZIhvcNAQkVMRYEFMbkckLpQhQd891xl1MJiI4JN/DuMD0GCSqGSIb3DQEJFDEwHi4ATgBlAHQAYgBvAHQAIABSAG8AbwB0ACAAQwBBACAAQwBTADIAVQBOAEIARABSMDAwITAJBgUrDgMCGgUABBTv0DZW5WGOyttIiEY23f3RInSpEwQIoXlbDNrNFtcCAQE=
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
