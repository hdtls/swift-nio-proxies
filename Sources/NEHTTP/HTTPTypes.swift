//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2022 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

// The MIT License (MIT)
//
// Copyright (c) 2020 Qutheory, LLC
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// THIS FILE IS MOSTLY COPIED FROM [vapor](https://github.com/vapor/vapor)

import Foundation
import HTTPTypes
import NIOHTTP1

let crlf: StaticString = "\r\n"

extension HTTPHeaders {

  /// A basic username and password.
  struct BasicAuthorization: Equatable {
    /// The username, sometimes an email address
    let username: String

    /// The plaintext password
    let password: String
  }

  var proxyBasicAuthorization: BasicAuthorization? {
    set {
      if let basic = newValue {
        let credentials = "\(basic.username):\(basic.password)"
        let encoded = Data(credentials.utf8).base64EncodedString()
        replaceOrAdd(name: "Proxy-Authorization", value: "Basic \(encoded)")
      } else {
        remove(name: "Proxy-Authorization")
      }
    }
    get {
      guard let string = self.first(name: "Proxy-Authorization") else {
        return nil
      }

      let headerParts = string.components(separatedBy: "Basic ")
      guard headerParts.count == 2 else {
        return nil
      }

      guard let data = Data(base64Encoded: headerParts[1]) else {
        return nil
      }

      let parts = String(decoding: data, as: UTF8.self).split(
        separator: ":",
        maxSplits: 1
      )

      guard parts.count == 2 else {
        return nil
      }

      return .init(username: .init(parts[0]), password: .init(parts[1]))
    }
  }
}

extension HTTPRequestHead {

  var host: String {
    let hostField = headers.first(name: "Host") ?? uri
    return hostField.components(separatedBy: ":").first ?? ""
  }

  var port: Int {
    let hostFields: [Substring] = headers.first(name: "Host")?.split(separator: ":") ?? []

    var port: Int?

    if hostFields.count >= 2 {
      // Standard host field
      port = Int(hostFields[1])
    }

    if let port {
      return port
    }

    let defaultPort = method == .CONNECT ? 443 : 80

    guard let portField = uri.split(separator: ":").last else {
      return defaultPort
    }
    return Int(portField) ?? defaultPort
  }
}

extension HTTPMethod {

  internal enum HasBody {
    case yes
    case no
    case unlikely
  }

  /// Whether requests with this verb may have a request body.
  internal var hasRequestBody: HasBody {
    switch self {
    case .TRACE:
      return .no
    case .POST, .PUT, .PATCH:
      return .yes
    case .GET, .CONNECT, .OPTIONS, .HEAD, .DELETE:
      fallthrough
    default:
      return .unlikely
    }
  }
}

extension ByteBuffer {

  /// Serializes this HTTP header block to bytes suitable for writing to the wire.
  ///
  /// - Parameter buffer: A buffer to write the serialized bytes into. Will increment
  ///     the writer index of this buffer.
  mutating func writeHTTPHeaders(_ headers: HTTPHeaders) {
    for field in headers {
      writeString(field.name)
      writeStaticString(": ")
      writeString(field.value)
      writeStaticString(crlf)
    }
    writeStaticString(crlf)
  }

  mutating func writeHTTPVersion(_ version: HTTPVersion) {
    switch (version.minor, version.major) {
    case (1, 0):
      writeStaticString("HTTP/1.0")
    case (1, 1):
      writeStaticString("HTTP/1.1")
    default:
      writeStaticString("HTTP/")
      writeString(String(version.major))
      writeStaticString(".")
      writeString(String(version.minor))
    }
  }

  mutating func writeHTTPRequestHead(_ request: HTTPRequestHead) {
    writeString(request.method.rawValue)
    writeWhitespace()
    writeString(request.uri)
    writeWhitespace()
    writeHTTPVersion(request.version)
    writeStaticString(crlf)
  }

  mutating func writeWhitespace() {
    writeInteger(32, as: UInt8.self)
  }
}

extension HTTPFields {

  /// Returns a new HTTPHeaders made by removing from all hop-by-hop fields.
  ///
  /// - Returns: The headers without hop-by-hop fields.
  mutating func trimmingHopByHopFields() {
    let fieldsToRemove = [
      HTTPField.Name("Proxy-Connection"),
      .proxyAuthenticate,
      .proxyAuthorization,
      .te,
      .trailer,
      .transferEncoding,
      .upgrade,
      .connection,
    ]

    for name in fieldsToRemove {
      self.removeAll { $0.name == name }
    }
  }
}
