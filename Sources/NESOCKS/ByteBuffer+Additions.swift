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

import NIOCore

extension ByteBuffer {

  mutating func readAuthenticationMethodRequest() -> Authentication.Method.Request? {
    guard let numberOfMethods = getInteger(at: readerIndex + 1, as: UInt8.self) else {
      return nil
    }

    guard readableBytes >= numberOfMethods + 2 else {
      return nil
    }

    let version = readInteger(as: UInt8.self)!
    moveReaderIndex(forwardBy: 1)

    // safe to bang as we've already checked the buffer size
    let methods = readBytes(length: Int(numberOfMethods))!.map {
      Authentication.Method(rawValue: $0)
    }

    return .init(version: .init(rawValue: version), methods: methods)
  }

  @discardableResult
  mutating func writeAuthenticationMethodRequest(_ request: Authentication.Method.Request) -> Int {
    var written = 0
    written += writeInteger(request.version.rawValue)
    written += writeInteger(UInt8(request.methods.count))

    request.methods.forEach {
      written += writeInteger($0.rawValue)
    }

    return written
  }

  mutating func readAuthenticationMethodResponse() -> Authentication.Method.Response? {
    guard readableBytes >= 2 else {
      return nil
    }

    let version = readInteger(as: UInt8.self)!
    let method = readInteger(as: UInt8.self)!

    return .init(version: .init(rawValue: version), method: .init(rawValue: method))
  }

  @discardableResult
  mutating func writeAuthenticationMethodResponse(_ method: Authentication.Method.Response) -> Int {
    return writeInteger(method.version.rawValue) + writeInteger(method.method.rawValue)
  }

  mutating func readAuthenticationRequest() -> Authentication.UsernameAuthenticationRequest? {
    var buffer = self

    guard
      let version = buffer.readInteger(as: UInt8.self),
      let lengthOfUsername = buffer.readInteger(as: UInt8.self),
      buffer.readableBytes >= lengthOfUsername
    else {
      return nil
    }

    let username = buffer.readString(length: Int(lengthOfUsername))!

    guard
      let lenthOfPassword = buffer.readInteger(as: UInt8.self),
      buffer.readableBytes >= lenthOfPassword
    else {
      return nil
    }

    let password = buffer.readString(length: Int(lenthOfPassword))!

    self = buffer

    return .init(version: version, username: username, password: password)
  }

  @discardableResult
  mutating func writeAuthenticationRequest(
    _ request: Authentication.UsernameAuthenticationRequest
  ) -> Int {
    var written = 0

    written += writeInteger(request.version)
    written += writeInteger(UInt8(request.username.count))
    written += writeString(request.username)
    written += writeInteger(UInt8(request.password.count))
    written += writeString(request.password)

    return written
  }

  mutating func readAuthenticationResponse() -> Authentication.UsernameAuthenticationResponse? {
    guard readableBytes >= 2 else {
      return nil
    }

    let version = readInteger(as: UInt8.self)!
    let status = readInteger(as: UInt8.self)!

    return .init(version: version, status: status)
  }

  @discardableResult
  mutating func writeAuthenticationResponse(
    _ response: Authentication.UsernameAuthenticationResponse
  )
    -> Int
  {
    var written = 0

    written += writeInteger(response.version)
    written += writeInteger(response.status)

    return written
  }

  mutating func readRequestDetails() throws -> Request? {
    var buffer = self

    guard
      let version = buffer.readInteger(as: UInt8.self),
      let command = buffer.readInteger(as: UInt8.self),
      let reserved = buffer.readInteger(as: UInt8.self),
      let address = try buffer.readAddress()
    else {
      return nil
    }

    self = buffer

    return .init(
      version: .init(rawValue: version),
      command: .init(rawValue: command),
      reserved: reserved,
      address: address
    )
  }

  @discardableResult
  mutating func writeRequestDetails(_ request: Request) -> Int {
    var written = writeInteger(request.version.rawValue)
    written += writeInteger(request.command.rawValue)
    written += writeInteger(UInt8.zero)
    written += writeAddress(request.address)
    return written
  }

  mutating func readServerResponse() throws -> Response? {
    var buffer = self
    guard
      let version = buffer.readInteger(as: UInt8.self),
      let reply = buffer.readInteger(as: UInt8.self).map(Response.Reply.init),
      let reserved = buffer.readInteger(as: UInt8.self),
      let boundAddress = try buffer.readAddress()
    else {
      return nil
    }

    self = buffer

    return .init(
      version: .init(rawValue: version),
      reply: reply,
      reserved: reserved,
      boundAddress: boundAddress
    )
  }

  @discardableResult
  mutating func writeServerResponse(_ response: Response) -> Int {
    writeInteger(response.version.rawValue)
      + writeInteger(response.reply.rawValue)
      + writeInteger(UInt8.zero) + writeAddress(response.boundAddress)
  }
}
