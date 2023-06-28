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

@testable import NEApp

final class ProxyTests: XCTestCase {

  let base64EncodedP12String =
    "MIIKPwIBAzCCCgYGCSqGSIb3DQEHAaCCCfc"

  func testDecodeProxy() throws {
    let proxyString =
      "{\"algorithm\":\"AES-256-GCM\",\"authenticationRequired\":true,\"certificatePinning\":\"MIIKPwIBAzCCCgYGCSqGSIb3DQEHAaCCCfc\",\"overTls\":true,\"passwordReference\":\"123456\",\"port\":8080,\"prefererHttpTunneling\":true,\"protocol\":\"http\",\"serverAddress\":\"127.0.0.1\",\"skipCertificateVerification\":true,\"sni\":\"example.com\",\"username\":\"test\"}"
    let proxy = try JSONDecoder().decode(Proxy.self, from: proxyString.data(using: .utf8)!)

    XCTAssertEqual(proxy.serverAddress, "127.0.0.1")
    XCTAssertEqual(proxy.port, 8080)
    XCTAssertEqual(proxy.protocol, .http)
    XCTAssertEqual(proxy.username, "test")
    XCTAssertEqual(proxy.passwordReference, "123456")
    XCTAssertEqual(proxy.authenticationRequired, true)
    XCTAssertEqual(proxy.prefererHttpTunneling, true)
    XCTAssertEqual(proxy.overTls, true)
    XCTAssertEqual(proxy.skipCertificateVerification, true)
    XCTAssertEqual(proxy.sni, "example.com")
    XCTAssertEqual(proxy.certificatePinning, base64EncodedP12String)
    XCTAssertEqual(proxy.algorithm, .aes256Gcm)
  }

  func testDefaultValueWorksWhenDecodingProxy() throws {
    let proxyString = "{\"port\":8080,\"protocol\":\"http\",\"serverAddress\":\"127.0.0.1\"}"

    let proxy = try JSONDecoder().decode(Proxy.self, from: proxyString.data(using: .utf8)!)

    XCTAssertEqual(proxy.serverAddress, "127.0.0.1")
    XCTAssertEqual(proxy.port, 8080)
    XCTAssertEqual(proxy.protocol, .http)
    XCTAssertEqual(proxy.username, "")
    XCTAssertEqual(proxy.passwordReference, "")
    XCTAssertEqual(proxy.authenticationRequired, false)
    XCTAssertEqual(proxy.prefererHttpTunneling, false)
    XCTAssertEqual(proxy.overTls, false)
    XCTAssertEqual(proxy.skipCertificateVerification, false)
    XCTAssertEqual(proxy.sni, "")
    XCTAssertEqual(proxy.certificatePinning, "")
  }

  func testEncodeProxy() throws {
    let expectedProxyString =
      "{\"algorithm\":\"AES-256-GCM\",\"authenticationRequired\":true,\"certificatePinning\":\"MIIKPwIBAzCCCgYGCSqGSIb3DQEHAaCCCfc\",\"overTls\":true,\"passwordReference\":\"123456\",\"port\":8080,\"prefererHttpTunneling\":true,\"protocol\":\"http\",\"serverAddress\":\"127.0.0.1\",\"skipCertificateVerification\":true,\"sni\":\"example.com\",\"username\":\"test\"}"

    let proxy = Proxy(
      serverAddress: "127.0.0.1",
      port: 8080,
      protocol: .http,
      username: "test",
      passwordReference: "123456",
      authenticationRequired: true,
      prefererHttpTunneling: true,
      overTls: true,
      skipCertificateVerification: true,
      sni: "example.com",
      certificatePinning: base64EncodedP12String,
      algorithm: .aes256Gcm
    )

    let encoder = JSONEncoder()
    encoder.outputFormatting = .sortedKeys
    let proxyString = String(data: try encoder.encode(proxy), encoding: .utf8)

    XCTAssertEqual(proxyString, expectedProxyString)
  }

  func testEncodeDefaultProxy() throws {
    let expectedProxyString =
      "{\"port\":8080,\"protocol\":\"http\",\"serverAddress\":\"127.0.0.1\"}"

    let proxy = Proxy(serverAddress: "127.0.0.1", port: 8080, protocol: .http)

    let encoder = JSONEncoder()
    encoder.outputFormatting = .sortedKeys
    let proxyString = String(data: try encoder.encode(proxy), encoding: .utf8)

    XCTAssertEqual(proxyString, expectedProxyString)
  }
}
