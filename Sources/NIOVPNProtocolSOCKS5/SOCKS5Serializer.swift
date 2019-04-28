//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright © 2019 Netbot Ltd. All rights reserved. and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation
import NIO

/// SOCKS5 Codable implemetation
class SOCKS5Serializer {

    /// SOCKS5 handshake step defination
    ///
    enum Step {
        case hello
        case authentication
        case replies
        case completion
    }

    private let kind: SOCKS5ProxyHandler.Mode
    var step: Step

    private var isFinished: Bool = false

    init(kind: SOCKS5ProxyHandler.Mode, step: Step) {
        self.kind = kind
        self.step = step
    }
}

extension SOCKS5Serializer: ByteToMessageDecoder {

    typealias InboundOut = Negotiation

    func decode(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws -> DecodingState {
        guard !isFinished else {
            return .needMoreData
        }

        switch step {
        case .hello:
            return try parseHello(context: context, buffer: &buffer)
        case .authentication:
            return try parseAuthentication(context: context, buffer: &buffer)
        case .replies:
            return try parseReplies(context: context, buffer: &buffer)
        case .completion:
            context.fireChannelRead(wrapInboundOut(.completion(buffer)))
            return .continue
        }
    }

    func decodeLast(context: ChannelHandlerContext, buffer: inout ByteBuffer, seenEOF: Bool) throws -> DecodingState {
        if !isFinished {
            return try decode(context: context, buffer: &buffer)
        }
        return .needMoreData
    }

    private func parseHello(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws -> DecodingState {
        if kind == .client {
            // The client connects to the server, and sends a version
            // identifier/method selection message:
            //
            // +----+----------+----------+
            // |VER | NMETHODS | METHODS  |
            // +----+----------+----------+
            // | 1  |    1     | 1 to 255 |
            // +----+----------+----------+
            //
            // The VER field is set to X'05' for this version of the protocol(Socks5).  The
            // NMETHODS field contains the number of method identifier octets that
            // appear in the METHODS field.

            guard let bytes = buffer.readBytes(length: 2) else {
                return .needMoreData
            }

            isFinished = true

            let version = bytes[0]
            let method = Method.init(rawValue: bytes[1])!

            let greeting = HelloResponse.init(version: .v5, method: method)

            context.fireChannelRead(wrapInboundOut(.hello(greeting)))

        } else {
            // The server selects from one of the methods given in METHODS, and
            // sends a METHOD selection message:
            //
            // +----+--------+
            // |VER | METHOD |
            // +----+--------+
            // | 1  |   1    |
            // +----+--------+
            //
            // If the selected METHOD is X'FF', none of the methods listed by the
            // client are acceptable, and the client MUST close the connection.
            //
            // The values currently defined for METHOD are:
            //
            //   o  X'00' NO AUTHENTICATION REQUIRED
            // o  X'01' GSSAPI
            // o  X'02' USERNAME/PASSWORD
            // o  X'03' to X'7F' IANA ASSIGNED
            // o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
            // o  X'FF' NO ACCEPTABLE METHODS

            guard buffer.readableBytes >= 2 else {
                return .needMoreData
            }

            let version: UInt8 = buffer.readInteger()!
            let numberOfMethods: UInt8 = buffer.readInteger()!

            // Second parse methods
            guard let bytes = buffer.readBytes(length: Int(numberOfMethods)) else {
                return .needMoreData
            }

            isFinished = true

            var methods: [Method] = []
            for byte in bytes {
                if let method = Method.init(rawValue: byte) {
                    methods.append(method)
                }
            }

            let greeting = HelloRequest.init(version: .v5, numberOfAuthMethods: numberOfMethods, methods: methods)
            context.fireChannelRead(wrapInboundOut(.hello(greeting)))
        }

        return .needMoreData
    }

    private func parseAuthentication(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws -> DecodingState {
        if kind == .client {
            // The server verifies the supplied UNAME and PASSWD, and sends the
            // following response:
            //
            // +----+--------+
            // |VER | STATUS |
            // +----+--------+
            // | 1  |   1    |
            // +----+--------+
            //
            // A STATUS field of X'00' indicates success. If the server returns a
            // `failure' (STATUS value other than X'00') status, it MUST close the
            // connection.

            let bytesAvaliable: Int = 2
            guard let bytes = buffer.readBytes(length: bytesAvaliable) else {
                return .needMoreData
            }

            let response = BasicAuthResponse.init(version: bytes[0], status: bytes[1])
            context.fireChannelRead(wrapInboundOut(.authentication(.basicAuth(response))))

        } else {
            // Once the SOCKS V5 server has started, and the client has selected the
            // Username/Password Authentication protocol, the Username/Password
            // subnegotiation begins.  This begins with the client producing a
            // Username/Password request:
            //
            // +----+------+----------+------+----------+
            // |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
            // +----+------+----------+------+----------+
            // | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
            // +----+------+----------+------+----------+
            // The VER field contains the current version of the subnegotiation,
            // which is X'01'. The ULEN field contains the length of the UNAME field
            // that follows. The UNAME field contains the username as known to the
            // source operating system. The PLEN field contains the length of the
            // PASSWD field that follows. The PASSWD field contains the password
            // association with the given UNAME.

            guard buffer.readableBytes > 2, let bytes = buffer.readBytes(length: 2) else {
                return .needMoreData
            }

            guard let usrnameBytes = buffer.readBytes(length: Int(bytes[1])) else {
                return .needMoreData
            }

            guard buffer.readableBytes > 1, let plen: UInt8 = buffer.readInteger() else {
                return .needMoreData
            }

            guard let pwdBytes = buffer.readBytes(length: Int(plen)) else {
                return .needMoreData
            }

            let request = BasicAuthRequest.init(version: bytes[0],
                                                uLength: bytes[1],
                                                username: usrnameBytes,
                                                pLength: plen,
                                                passwd: pwdBytes)

            context.fireChannelRead(wrapInboundOut(.authentication(.basicAuth(request))))
        }

        return .needMoreData
    }

    private func parseReplies(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws -> DecodingState {
        if kind == .client {
            // The SOCKS request information is sent by the client as soon as it has
            // established a connection to the SOCKS server, and completed the
            // authentication negotiations.  The server evaluates the request, and
            // returns a reply formed as follows:
            //
            // +----+-----+-------+------+----------+----------+
            // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
            // +----+-----+-------+------+----------+----------+
            // | 1  |  1  | X'00' |  1   | Variable |    2     |
            // +----+-----+-------+------+----------+----------+
            //
            // Where:
            //
            // o  VER    protocol version: X'05'
            // o  REP    Reply field:
            //  o  X'00' succeeded
            //  o  X'01' general SOCKS server failure
            //  o  X'02' connection not allowed by ruleset
            //  o  X'03' Network unreachable
            //  o  X'04' Host unreachable
            //  o  X'05' Connection refused
            //  o  X'06' TTL expired
            //  o  X'07' Command not supported
            //  o  X'08' Address type not supported
            //  o  X'09' to X'FF' unassigned
            // o  RSV    RESERVED
            // o  ATYP   address type of following address
            //  o  IP V4 address: X'01'
            //  o  DOMAINNAME: X'03'
            //  o  IP V6 address: X'04'
            // o  BND.ADDR       server bound address
            // o  BND.PORT       server bound port in network octet order
            //
            // Fields marked RESERVED (RSV) must be set to X'00'.
            //
            // If the chosen method includes encapsulation for purposes of
            // authentication, integrity and/or confidentiality, the replies are
            // encapsulated in the method-dependent encapsulation.

            guard let bytes = buffer.readBytes(length: 4) else {
                return .needMoreData
            }

            let version = bytes[0]
            let reply = Reply.init(rawValue: bytes[1])!
            let reserved = bytes[2]
            let atyp = ATYP.init(rawValue: bytes[3])!
            var readLength: UInt8 = 0

            switch atyp {
            case .ipv4: readLength = 4
            case .ipv6: readLength = 16
            case .domainLength: readLength = buffer.readInteger() ?? 0
            }

            guard readLength > 0, let ipBuffer = buffer.readBytes(length: Int(readLength)) else {
                return .needMoreData
            }

            guard let portBuffer = buffer.readBytes(length: 2) else {
                return .needMoreData
            }

            isFinished = true

            let replies = RELReply.init(version: .v5,
                                        reply: reply,
                                        reserved: reserved,
                                        addressType: atyp,
                                        desiredDestinationAddress: ipBuffer,
                                        desiredDestinationPort: portBuffer)

            context.fireChannelRead(wrapInboundOut(.replies(replies)))
        } else {
            // Once the method-dependent subnegotiation has completed, the client
            // sends the request details.  If the negotiated method includes
            // encapsulation for purposes of integrity checking and/or
            // confidentiality, these requests MUST be encapsulated in the method-
            // dependent encapsulation.
            //
            // The SOCKS request is formed as follows:
            //
            // +----+-----+-------+------+----------+----------+
            // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
            // +----+-----+-------+------+----------+----------+
            // | 1  |  1  | X'00' |  1   | Variable |    2     |
            // +----+-----+-------+------+----------+----------+
            //
            // Where:
            //
            // o  VER    protocol version: X'05'
            // o  CMD
            //  o  CONNECT X'01'
            //  o  BIND X'02'
            //  o  UDP ASSOCIATE X'03'
            // o  RSV    RESERVED
            // o  ATYP   address type of following address
            //  o  IP V4 address: X'01'
            //  o  DOMAINNAME: X'03'
            //  o  IP V6 address: X'04'
            // o  DST.ADDR       desired destination address
            // o  DST.PORT desired destination port in network octet order
            //
            // The SOCKS server will typically evaluate the request based on source
            // and destination addresses, and return one or more reply messages, as
            // appropriate for the request type.

            guard let bytes = buffer.readBytes(length: 4) else {
                return .needMoreData
            }

            let version = bytes[0]
            let cmd = CMD.init(rawValue: bytes[1])!
            let reserved = bytes[2]
            let atyp = ATYP.init(rawValue: bytes[3])!
            var readLength: UInt8 = 0

            switch atyp {
            case .ipv4: readLength = 4
            case .ipv6: readLength = 16
            case .domainLength: readLength = buffer.readInteger() ?? 0
            }

            guard readLength > 0, let ipBuffer = buffer.readBytes(length: Int(readLength)) else {
                return .needMoreData
            }

            guard let portBuffer = buffer.readBytes(length: 2) else {
                return .needMoreData
            }

            isFinished = true

            let replies = RELRequest.init(version: .v5,
                                          cmd: cmd,
                                          reserved: reserved,
                                          addressType: atyp,
                                          desiredDestinationAddress: ipBuffer,
                                          desiredDestinationPort: portBuffer)

            context.fireChannelRead(wrapInboundOut(.replies(replies)))
        }

        return .needMoreData
    }
}

extension SOCKS5Serializer: MessageToByteEncoder {

    typealias OutboundIn = Negotiation

    func encode(data: Negotiation, out: inout ByteBuffer) throws {

            switch data {
            case .hello(let greeting):
                try encodeGreeting(data: greeting, out: &out)
            case .authentication(let authentication):
                try encodeAuthentication(data: authentication, out: &out)
            case .replies(let replies):
                try encodeReplies(data: replies, out: &out)
            case .completion(var buffer):
                out.writeBuffer(&buffer)
        }
    }

    private func encodeGreeting(data: Any, out: inout ByteBuffer) throws {
        switch data {
        case let payload as HelloRequest:
            out.writeInteger(payload.version.rawValue)
            out.writeInteger(payload.numberOfAuthMethods)
            payload.methods.forEach { (method) in
                out.writeInteger(method.rawValue)
            }
        case let payload as HelloResponse:
            out.writeInteger(payload.version.rawValue)
            out.writeInteger(payload.method.rawValue)
        default:
            fatalError("This should never happen")
        }
    }

    private func encodeAuthentication(data: Any, out: inout ByteBuffer) throws {

        switch data {
        case let payload as BasicAuthRequest:

            out.writeInteger(payload.version)
            out.writeInteger(UInt8(payload.uLength))
            out.writeBytes(payload.username)
            out.writeInteger(UInt8(payload.pLength))
            out.writeBytes(payload.passwd)

        case let payload as BasicAuthResponse:

            out.writeInteger(payload.version)
            out.writeInteger(payload.status)

        default:
            fatalError("This should never happen")
        }
    }

    private func encodeReplies(data: Any, out: inout ByteBuffer) throws {

        switch data {
        case let payload as RELRequest:

            out.writeInteger(payload.version.rawValue)
            out.writeInteger(payload.cmd.rawValue)
            out.writeInteger(payload.reserved)
            out.writeInteger(payload.addressType.rawValue)
            out.writeBytes(payload.desiredDestinationAddress)
            out.writeBytes(payload.desiredDestinationPort)

        case let payload as RELReply:

            out.writeInteger(payload.version.rawValue)
            out.writeInteger(payload.reply.rawValue)
            out.writeInteger(payload.reserved)
            out.writeInteger(payload.addressType.rawValue)
            out.writeBytes(payload.desiredDestinationAddress)
            out.writeBytes(payload.desiredDestinationPort)

        default:
            fatalError("This should never happen")
        }
    }
}
