//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2022 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation
import HTTPTypes
import NIOCore
import NIOHTTP1

let crlf: StaticString = "\r\n"

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

enum HTTPTypesError: Error {
  case invalidHTTPMethod
  case missingURIPart
}

extension HTTPRequest {
  init(_ head: HTTPRequestHead) throws {
    var scheme = head.method == .CONNECT ? "https" : "http"
    var authority: String = head.method == .CONNECT ? head.uri : ""
    var port: Int
    var host = head.headers["Host"].first ?? ""
    var path = head.method == .CONNECT ? "" : head.uri
    var components = head.uri.components(separatedBy: "://")
    if components.count > 1 {
      scheme = components.removeFirst()
    }

    components = components[0].components(separatedBy: "/").filter { !$0.isEmpty }
    guard !components.isEmpty else {
      throw HTTPTypesError.missingURIPart
    }
    authority = components.removeFirst()
    path = components.joined(separator: "/")
    components = authority.components(separatedBy: ":")
    if components.count > 1 {
      port = Int(components.removeLast()) ?? (scheme == "https" ? 443 : 80)
    } else {
      port = scheme == "https" ? 443 : 80
    }
    host = host.isEmpty ? components.removeFirst() : host
    authority = "\(host):\(port)"

    guard let method = Method(rawValue: head.method.rawValue) else {
      throw HTTPTypesError.invalidHTTPMethod
    }
    self.init(
      method: method,
      scheme: scheme,
      authority: authority,
      path: path,
      headerFields: .init(head.headers, splitCookie: true)
    )
  }
}

extension HTTPRequestHead {
  init(_ req: HTTPRequest, version: HTTPVersion) throws {
    var headers = HTTPHeaders()
    headers.reserveCapacity(req.headerFields.count + 1)
    guard let authority = req.authority else {
      throw HTTPTypesError.missingURIPart
    }
    if let host = authority.split(separator: ":").first {
      headers.add(name: "Host", value: String(host))
    }
    var firstCookie = true
    for field in req.headerFields {
      if field.name == .cookie {
        if firstCookie {
          firstCookie = false
          headers.add(name: field.name.rawName, value: req.headerFields[.cookie]!)
        }
      } else {
        headers.add(name: field.name.rawName, value: field.value)
      }
    }

    var path = req.path ?? ""
    path = path.hasPrefix("/") ? path : (path.isEmpty ? "" : "/" + path)
    let uri = req.method == .connect ? authority : "\(authority)\(path)"
    self.init(
      version: version,
      method: HTTPMethod(rawValue: req.method.rawValue),
      uri: uri,
      headers: headers
    )
  }
}

extension HTTPFields {
  init(_ headers: HTTPHeaders, splitCookie: Bool) {
    self.init()
    self.reserveCapacity(count)
    var firstHost = true
    for field in headers {
      if firstHost && field.name.lowercased() == "host" {
        firstHost = false
        continue
      }
      if let name = HTTPField.Name(field.name) {
        if splitCookie && name == .cookie,
          #available(macOS 13.0, iOS 16.0, watchOS 9.0, tvOS 16.0, *)
        {
          self.append(
            contentsOf: field.value.split(separator: "; ", omittingEmptySubsequences: false).map {
              HTTPField(name: name, value: String($0))
            }
          )
        } else {
          self.append(HTTPField(name: name, value: field.value))
        }
      }
    }
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

extension HTTPHeaders {
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
      if let name {
        self.remove(name: name.rawName)
      }
    }
  }
}
