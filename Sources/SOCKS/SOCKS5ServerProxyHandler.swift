//===----------------------------------------------------------------------===//
//
// This source file is part of the swift-nio-Netbot open source project
//
// Copyright © 2019 Netbot Ltd. and the swift-nio-Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIO

/// A channel handler that wraps a channel in SOCKS5 proxy using NIOVPNProtoSOCKS5.
/// This handler can be used in channels that are acting as the client
/// in the SOCKS5 dialog. For server connections, use the `SOCKS5ClientProxyHandler`.
public final class SOCKS5ServerProxyHandler: SOCKS5ProxyHandler {

    private var isValid: Bool = false
    private var REPL: ByteBuffer?

    public var configuration: ProxyConfiguration

    public init(configuration: ProxyConfiguration) {
        self.configuration = configuration
        super.init()
    }

    override public func recvHMsg(context: ChannelHandlerContext, byteBuffer: inout ByteBuffer) throws {
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

        guard byteBuffer.readableBytes >= 2 else {
            throw SOCKS5ProxyError.serializeFailed(reason: .needMoreBytes)
        }

        byteBuffer.moveReaderIndex(forwardBy: 1)
        let numberOfMethods: UInt8 = byteBuffer.readInteger()!

        guard byteBuffer.readableBytes >= Int(numberOfMethods) else {
            throw SOCKS5ProxyError.serializeFailed(reason: .needMoreBytes)
        }

        let methods = byteBuffer.readBytes(length: Int(numberOfMethods))!.map(Method.init)

        guard methods.contains(method) else {
            // TODO: Error out
//            context.fireErrorCaught(<#T##error: Error##Error#>)
            return
        }

        writeHMsg(context: context)
    }
    
    override public func writeHMsg(context: ChannelHandlerContext) {
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

        var byteBuffer = context.channel.allocator.buffer(capacity: 2)
        byteBuffer.writeInteger(Version.v5.rawValue)
        byteBuffer.writeInteger(method.rawValue)

        context.writeAndFlush(wrapOutboundOut(byteBuffer), promise: nil)
    }

    override public func recvAMsg(context: ChannelHandlerContext, byteBuffer: inout ByteBuffer) throws {

        switch method {
        case .noAuth:
            assertionFailure("This should never happen.")
        case .basicAuth:
            try recvBasicAMsg(context: context, byteBuffer: &byteBuffer)
            writeAMsg(context: context)
        default:
            // TODO: - METHOD specific negotation implemention.
            assertionFailure("METHOD specific negotiation not implemented.")
        }
    }

    override public func writeAMsg(context: ChannelHandlerContext) {

        switch method {
        case .noAuth:
            assertionFailure("This should never happen.")
        case .basicAuth:
            writeBasicAMsg(context: context)
        default:
            // TODO: - METHOD specific negotation implemention.
            assertionFailure("METHOD specific negotiation not implemented.")
        }
    }

    override public func recvRELMsg(context: ChannelHandlerContext, byteBuffer: inout ByteBuffer) throws {
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
        // o   IP V4 address: X'01'
        // o   DOMAINNAME: X'03'
        // o   IP V6 address: X'04'
        // o  DST.ADDR       desired destination address
        // o  DST.PORT desired destination port in network octet order
        //
        // The SOCKS server will typically evaluate the request based on source
        // and destination addresses, and return one or more reply messages, as
        // appropriate for the request type.

        guard byteBuffer.readableBytes >= 4 else {
            throw SOCKS5ProxyError.serializeFailed(reason: .needMoreBytes)
        }

        byteBuffer.moveReaderIndex(forwardBy: 1)
        let cmd = CMD.init(rawValue: byteBuffer.readInteger()!)

        byteBuffer.moveReaderIndex(forwardBy: 3)

        let family = ATYP.init(rawValue: byteBuffer.readInteger()!)

        let ipAddr: [UInt8]

        switch family {
        case .some(.ipv4):
            // size of ipv4 address: 4
            guard byteBuffer.readableBytes >= 4 else {
                throw SOCKS5ProxyError.serializeFailed(reason: .needMoreBytes)
            }

            ipAddr = byteBuffer.readBytes(length: 4)!
        case .some(.domainLength):
            guard byteBuffer.readableBytes >= 1 else {
                throw SOCKS5ProxyError.serializeFailed(reason: .needMoreBytes)
            }

            let copyLength: UInt8 = byteBuffer.readInteger()!
            guard byteBuffer.readableBytes >= Int(copyLength) else {
                throw SOCKS5ProxyError.serializeFailed(reason: .needMoreBytes)
            }

            ipAddr = byteBuffer.readBytes(length: Int(copyLength))!
        case .some(.ipv6):
            // size of ipv6 address: 16
            guard byteBuffer.readableBytes >= 16 else {
                throw SOCKS5ProxyError.serializeFailed(reason: .needMoreBytes)
            }

            ipAddr = byteBuffer.readBytes(length: 16)!
        default:
            throw SOCKS5ProxyError.serializeFailed(reason: .invalidInputBytes)
        }

        guard byteBuffer.readableBytes >= 2 else {
            throw SOCKS5ProxyError.serializeFailed(reason: .needMoreBytes)
        }

        let port = byteBuffer.readBytes(length: 2)!

        // TODO: - SOCKS5 server should typically evaluate the request base on
        // source and destination address.

        REPL = context.channel.allocator.buffer(capacity: byteBuffer.readableBytes)

        REPL?.writeInteger(Version.v5.rawValue)
        REPL?.writeInteger(Reply.succeeded.rawValue)
        REPL?.writeInteger(SOCKS5_HANDSHAKE_REL_RSV_CODE)
        REPL?.writeInteger(family!.rawValue)
        if family! == .domainLength {
            REPL?.writeInteger(UInt8(ipAddr.count))
        }
        REPL?.writeBytes(ipAddr)
        REPL?.writeBytes(port)

        writeRELMsg(context: context)
    }

    public override func writeRELMsg(context: ChannelHandlerContext) {
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

        guard let byteBuffer = REPL else {
            assertionFailure("REPL should not be nil")
            return
        }
        context.writeAndFlush(wrapOutboundOut(byteBuffer), promise: nil)
    }
}

extension SOCKS5ServerProxyHandler: RFC1919 {

    public func recvBasicAMsg(context: ChannelHandlerContext, byteBuffer: inout ByteBuffer) throws {
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

        guard let auth = configuration.basicAuthorization else {
            assertionFailure("Username/Password authentication protocol require authorization info.")
            return
        }

        guard byteBuffer.readableBytes >= 2 else {
            throw SOCKS5ProxyError.serializeFailed(reason: .needMoreBytes)
        }

        byteBuffer.moveReaderIndex(forwardBy: 1)

        let uLength: UInt8 = byteBuffer.readInteger()!

        guard byteBuffer.readableBytes >= uLength else {
            throw SOCKS5ProxyError.serializeFailed(reason: .needMoreBytes)
        }

        let username = byteBuffer.readString(length: Int(uLength))

        guard byteBuffer.readableBytes >= 1 else {
            throw SOCKS5ProxyError.serializeFailed(reason: .needMoreBytes)
        }

        let pLength: UInt8 = byteBuffer.readInteger()!

        guard byteBuffer.readableBytes >= pLength else {
            throw SOCKS5ProxyError.serializeFailed(reason: .needMoreBytes)
        }

        let pwd = byteBuffer.readString(length: Int(pLength))

        isValid = username == auth.username && pwd == auth.password

        guard isValid else {
            throw SOCKS5ProxyError.authenticationFailed(reason: .incorrectUsernameOrPassword)
        }

        writeAMsg(context: context)
    }

    public func writeBasicAMsg(context: ChannelHandlerContext) {
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
        // `failure' (STATUS value other than X'00') status, it MUST close the connection.

        var byteBuffer = context.channel.allocator.buffer(capacity: 2)

        byteBuffer.writeInteger(SOCKS5_BASIC_AUTH_VERSION)
        byteBuffer.writeInteger(isValid ? SOCKS5_BASIC_AUTH_SUCCESS_CODE : SOCKS5_BASIC_AUTH_FAILURE_CODE)

        context.writeAndFlush(wrapOutboundOut(byteBuffer), promise: nil)
    }
}
