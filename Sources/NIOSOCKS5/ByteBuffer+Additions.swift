//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2022 Junfeng Zhang. and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation

extension ByteBuffer {

    mutating func readAuthenticationMethodRequest() throws -> Authentication.Method.Request? {
        try parseUnwindingIfNeeded { buffer in
            guard
                try buffer.readAndValidateProtocolVersion() != nil,
                let numMethods = buffer.readInteger(as: UInt8.self),
                buffer.readableBytes >= numMethods
            else {
                return nil
            }

            // safe to bang as we've already checked the buffer size
            let methods = buffer.readBytes(length: Int(numMethods))!.map {
                Authentication.Method(rawValue: $0)
            }
            return .init(methods: methods)
        }
    }

    @discardableResult
    mutating func writeAuthenticationMethodRequest(_ request: Authentication.Method.Request) -> Int
    {
        var written = 0
        written += writeInteger(request.version.rawValue)
        written += writeInteger(UInt8(request.methods.count))

        request.methods.forEach {
            written += writeInteger($0.rawValue)
        }

        return written
    }

    mutating func readAuthenticationMethodResponse() throws -> Authentication.Method.Response? {
        return try parseUnwindingIfNeeded { buffer in
            guard
                try buffer.readAndValidateProtocolVersion() != nil,
                let method = buffer.readInteger(as: UInt8.self)
            else {
                return nil
            }
            return .init(method: .init(rawValue: method))
        }
    }

    @discardableResult
    mutating func writeAuthenticationMethodResponse(_ method: Authentication.Method.Response) -> Int
    {
        return writeInteger(method.version.rawValue) + writeInteger(method.method.rawValue)
    }

    mutating func readAuthenticationRequest() -> Authentication.UsernameAuthenticationRequest? {
        parseUnwindingIfNeeded { buffer in
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

            return .init(version: version, username: username, password: password)
        }
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
        parseUnwindingIfNeeded { buffer in
            guard let version = buffer.readInteger(as: UInt8.self),
                let status = buffer.readInteger(as: UInt8.self)
            else {
                return nil
            }

            return .init(version: version, status: status)
        }
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

    @discardableResult
    mutating func writeServerMessage(_ message: ServerMessage) -> Int {
        switch message {
            case .selectedAuthenticationMethod(let method):
                return writeAuthenticationMethodResponse(method)
            case .response(let response):
                return writeServerResponse(response)
            case .authenticationData(var buffer, _):
                return writeBuffer(&buffer)
        }
    }

    mutating func readRequestDetails() throws -> Request? {
        try parseUnwindingIfNeeded { buffer -> Request? in
            guard
                try buffer.readAndValidateProtocolVersion() != nil,
                let command = buffer.readInteger(as: UInt8.self),
                try buffer.readAndValidateReserved() != nil,
                let address = try buffer.readAddress()
            else {
                return nil
            }
            return .init(command: .init(rawValue: command), address: address)
        }
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
        return try parseUnwindingIfNeeded { buffer in
            guard
                try buffer.readAndValidateProtocolVersion() != nil,
                let reply = buffer.readInteger(as: UInt8.self).map({ Response.Reply(rawValue: $0) }
                ),
                try buffer.readAndValidateReserved() != nil,
                let boundAddress = try buffer.readAddress()
            else {
                return nil
            }
            return .init(reply: reply, boundAddress: boundAddress)
        }
    }

    @discardableResult
    mutating func writeServerResponse(_ response: Response) -> Int {
        writeInteger(response.version.rawValue) + writeInteger(response.reply.rawValue)
            + writeInteger(UInt8.zero) + writeAddress(response.boundAddress)
    }

    mutating func readAndValidateProtocolVersion() throws -> UInt8? {
        return try parseUnwindingIfNeeded { buffer -> UInt8? in
            guard let version = buffer.readInteger(as: UInt8.self) else {
                return nil
            }
            guard version == 0x05 else {
                throw SOCKSError.unsupportedProtocolVersion(actual: version)
            }
            return version
        }
    }

    mutating func readAndValidateReserved() throws -> UInt8? {
        return try parseUnwindingIfNeeded { buffer -> UInt8? in
            guard let reserved = buffer.readInteger(as: UInt8.self) else {
                return nil
            }
            guard reserved == 0x00 else {
                throw SOCKSError.invalidReservedByte(actual: reserved)
            }
            return reserved
        }
    }
}
