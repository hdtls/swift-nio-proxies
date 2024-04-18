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

import HTTPTypes
import XCTest

@testable import NEHTTP

final class HTTPTypesTests: XCTestCase {

  func testTrimmingHopByHop() {
    var httpFields = HTTPFields()
    httpFields.append(HTTPField(name: .proxyAuthorization, value: "Bearer <token>"))
    httpFields.trimmingHopByHopFields()
    XCTAssertFalse(httpFields.contains(.proxyAuthorization))
  }

  func testParseBasicAuthorizationFromHTTPHeadersWithoutAuthorizationField() {
    let headers = HTTPHeaders()
    XCTAssertNil(headers.proxyBasicAuthorization)
  }

  func testParseBasicAuthorizationFromHTTPHeadersWitchAuthorizationFieldIsNotBasicAuthorization() {
    var headers = HTTPHeaders()
    headers.add(name: "Proxy-Authorization", value: "Bearer <token>")
    XCTAssertNil(headers.proxyBasicAuthorization)
  }

  func testParseBasicAuthorizationFromHTTPHeadersWitchAuthorizationFieldIsInvalid() {
    var headers = HTTPHeaders()
    headers.add(name: "Proxy-Authorization", value: "Basic <token>")
    XCTAssertNil(headers.proxyBasicAuthorization)

    headers.replaceOrAdd(name: "Proxy-Authorization", value: "Basic cGFzc3dvcmQ=")
    XCTAssertNil(headers.proxyBasicAuthorization)
  }

  func testParseBasicAuthorization() {
    var headers = HTTPHeaders()
    headers.add(name: "Proxy-Authorization", value: "Basic dGVzdDpwYXNzd29yZA==")

    XCTAssertNotNil(headers.proxyBasicAuthorization)

    XCTAssertEqual(headers.proxyBasicAuthorization?.username, "test")
    XCTAssertEqual(headers.proxyBasicAuthorization?.password, "password")
  }

  func testSetBasicAuthorizationForHTTPHeaders() {
    var headers = HTTPHeaders()
    headers.proxyBasicAuthorization = .init(username: "test", password: "password")
    XCTAssertEqual(headers.first(name: "Proxy-Authorization"), "Basic dGVzdDpwYXNzd29yZA==")

    headers.proxyBasicAuthorization = .init(username: "replacePreviouse", password: "password")
    XCTAssertEqual(
      headers.first(name: "Proxy-Authorization"),
      "Basic cmVwbGFjZVByZXZpb3VzZTpwYXNzd29yZA=="
    )

    headers.proxyBasicAuthorization = nil
    XCTAssertFalse(headers.contains(name: "Proxy-Authorization"))
  }

  func testGetTheHostAndPortFromTheRequestHeadWhoseHostFieldContainsBothHostnameAndPort() {
    let head = HTTPRequestHead(
      version: .http1_1,
      method: .CONNECT,
      uri: "swift.org:443",
      headers: ["Host": "swift.org:443"]
    )
    XCTAssertEqual(head.host, "swift.org")
    XCTAssertEqual(head.port, 443)
  }

  func testGetTheHostAndPortFromTheRequestHeadWhoseHostFieldOnlyContainsHostname() {
    let head = HTTPRequestHead(
      version: .http1_1,
      method: .CONNECT,
      uri: "swift.org:443",
      headers: ["Host": "swift.org"]
    )
    XCTAssertEqual(head.host, "swift.org")
    XCTAssertEqual(head.port, 443)
  }

  func testGetTheHostAndPortFromTheRequestHeadWhoseHostFieldIsMissing() {
    let head = HTTPRequestHead(version: .http1_1, method: .CONNECT, uri: "swift.org:443")
    XCTAssertEqual(head.host, "swift.org")
    XCTAssertEqual(head.port, 443)
  }

  func testGetPortFromTheRequestHeadContainingOnlyTheHostnameInBothURIAndHostField() {
    let head = HTTPRequestHead(version: .http1_1, method: .CONNECT, uri: "swift.org")
    XCTAssertEqual(head.port, 443)
  }

  func testWriteHTTPHeaders() {
    let headers = HTTPHeaders([("host", "example.com"), ("proxy-connection", "keep-alive")])
    let expected = "host: example.com\r\nproxy-connection: keep-alive\r\n\r\n"

    var byteBuffer = ByteBuffer()
    byteBuffer.writeHTTPHeaders(headers)

    XCTAssertEqual(String(buffer: byteBuffer), expected)
  }

  func testWriteHTTPVersion() {
    let httpVersion = HTTPVersion.http1_1
    let expected = "HTTP/1.1"

    var byteBuffer = ByteBuffer()
    byteBuffer.writeHTTPVersion(httpVersion)

    XCTAssertEqual(String(buffer: byteBuffer), expected)
  }

  func testWriteHTTPRequestHead() {
    let request = HTTPRequestHead(
      version: .http1_1,
      method: .CONNECT,
      uri: "/uri",
      headers: HTTPHeaders([("transfer-encoding", "chunked")])
    )
    let expected = "CONNECT /uri HTTP/1.1\r\n"

    var byteBuffer = ByteBuffer()
    byteBuffer.writeHTTPRequestHead(request)

    XCTAssertEqual(String(buffer: byteBuffer), expected)
  }
}
