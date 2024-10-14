//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2023 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import HTTPTypes
import NIOCore
import NIOHTTP1
import XCTest

@testable import NEHTTP

final class HTTPTypesTests: XCTestCase {

  func testTrimmingHopByHop() {
    var httpFields = HTTPFields()
    httpFields.append(HTTPField(name: .proxyAuthorization, value: "Bearer <token>"))
    httpFields.trimmingHopByHopFields()
    XCTAssertFalse(httpFields.contains(.proxyAuthorization))
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

  func testConvertHTTPRequestFromHTTPRequestHead() throws {
    var source = HTTPRequestHead(
      version: .http1_1,
      method: .CONNECT,
      uri: "swift.org:443",
      headers: .init([("Host", "swift.org")])
    )
    var req = try HTTPRequest(source)
    XCTAssertEqual(req.method, .connect)
    XCTAssertEqual(req.scheme, "https")
    XCTAssertEqual(req.authority, "swift.org:443")
    XCTAssertEqual(req.path, "")
    XCTAssertEqual(req.headerFields, HTTPFields([]))

    source = HTTPRequestHead(
      version: .http1_1,
      method: .CONNECT,
      uri: "swift.org",
      headers: .init()
    )
    req = try HTTPRequest(source)
    XCTAssertEqual(req.method, .connect)
    XCTAssertEqual(req.scheme, "https")
    XCTAssertEqual(req.authority, "swift.org:443")
    XCTAssertEqual(req.path, "")
    XCTAssertEqual(req.headerFields, HTTPFields([]))

    source = HTTPRequestHead(
      version: .http1_1,
      method: .GET,
      uri: "https://swift.org/swift-evolution",
      headers: .init()
    )
    req = try HTTPRequest(source)
    XCTAssertEqual(req.method, .get)
    XCTAssertEqual(req.scheme, "https")
    XCTAssertEqual(req.authority, "swift.org:443")
    XCTAssertEqual(req.path, "swift-evolution")
    XCTAssertEqual(req.headerFields, HTTPFields([]))

    source = HTTPRequestHead(
      version: .http1_1,
      method: .GET,
      uri: "http://swift.org/swift-evolution",
      headers: .init()
    )
    req = try HTTPRequest(source)
    XCTAssertEqual(req.method, .get)
    XCTAssertEqual(req.scheme, "http")
    XCTAssertEqual(req.authority, "swift.org:80")
    XCTAssertEqual(req.path, "swift-evolution")
    XCTAssertEqual(req.headerFields, HTTPFields([]))

    source = HTTPRequestHead(
      version: .http1_1,
      method: .GET,
      uri: "swift.org/swift-evolution",
      headers: .init()
    )
    req = try HTTPRequest(source)
    XCTAssertEqual(req.method, .get)
    XCTAssertEqual(req.scheme, "http")
    XCTAssertEqual(req.authority, "swift.org:80")
    XCTAssertEqual(req.path, "swift-evolution")
    XCTAssertEqual(req.headerFields, HTTPFields([]))

    source = HTTPRequestHead(version: .http1_1, method: .GET, uri: "", headers: .init())
    XCTAssertThrowsError(try HTTPRequest(source))
  }

  func testConvertHTTPRequestHeadFromHTTPRequest() throws {
    var source = HTTPRequest(
      method: .connect,
      scheme: nil,
      authority: "swift.org:443",
      path: nil,
      headerFields: HTTPFields()
    )
    var req = try HTTPRequestHead(source, version: .http1_1)
    XCTAssertEqual(req.method, .CONNECT)
    XCTAssertEqual(req.uri, "swift.org:443")
    XCTAssertEqual(req.headers, HTTPHeaders([("Host", "swift.org")]))

    source = HTTPRequest(
      method: .get,
      scheme: "https",
      authority: "swift.org:443",
      path: "swift-evolution",
      headerFields: HTTPFields()
    )
    req = try HTTPRequestHead(source, version: .http1_1)
    XCTAssertEqual(req.method, .GET)
    XCTAssertEqual(req.uri, "swift.org:443/swift-evolution")
    XCTAssertEqual(req.headers, HTTPHeaders([("Host", "swift.org")]))

    source = HTTPRequest(
      method: .get,
      scheme: "https",
      authority: nil,
      path: "swift-evolution",
      headerFields: HTTPFields()
    )
    XCTAssertThrowsError(try HTTPRequestHead(source, version: .http1_1))

    source = HTTPRequest(
      method: .get,
      scheme: "https",
      authority: "swift.org:443",
      path: "/swift-evolution",
      headerFields: HTTPFields()
    )
    req = try HTTPRequestHead(source, version: .http1_1)
    XCTAssertEqual(req.method, .GET)
    XCTAssertEqual(req.uri, "swift.org:443/swift-evolution")
    XCTAssertEqual(req.headers, HTTPHeaders([("Host", "swift.org")]))

    source = HTTPRequest(
      method: .connect,
      scheme: "https",
      authority: "swift.org:443",
      path: nil,
      headerFields: HTTPFields()
    )
    req = try HTTPRequestHead(source, version: .http1_1)
    XCTAssertEqual(req.method, .CONNECT)
    XCTAssertEqual(req.uri, "swift.org:443")
    XCTAssertEqual(req.headers, HTTPHeaders([("Host", "swift.org")]))
  }
}
