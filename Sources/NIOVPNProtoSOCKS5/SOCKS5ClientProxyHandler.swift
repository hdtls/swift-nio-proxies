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
public final class SOCKS5ClientProxyHandler: SOCKS5ProxyHandler {

    public var configuration: ProxyConfiguration

    public init(configuration: ProxyConfiguration, completion: @escaping (SLPNResult) -> EventLoopFuture<Void>) {
        self.configuration = configuration

        super.init(completion: completion)
    }

    public func handlerAdded(context: ChannelHandlerContext) {
        super.handlerAdded(context: context)

        // If channel active event has been fired already, which means `channelActive` will
        // not be invoked. We have to initialize here instead.
        if context.channel.isActive {
            writeHMsg(context: context)
        }
    }

    public func channelActive(context: ChannelHandlerContext) {
        context.fireChannelActive()
        writeHMsg(context: context)
    }

    override public func writeHMsg(context: ChannelHandlerContext) {
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

        var byteBuffer = context.channel.allocator.buffer(capacity: 3)

        byteBuffer.writeInteger(Version.v5.rawValue)
        byteBuffer.writeInteger(UInt8(1))
        if configuration.basicAuthorization != nil {
            byteBuffer.writeInteger(Method.basicAuth.rawValue)
        } else {
            byteBuffer.writeInteger(Method.noAuth.rawValue)
        }

        context.writeAndFlush(wrapOutboundOut(byteBuffer), promise: nil)
    }

    override public func recvHMsg(context: ChannelHandlerContext, byteBuffer: inout ByteBuffer) throws {
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

        guard byteBuffer.readableBytes >= 2 else {
            throw SOCKS5ProxyError.serializeFailed(reason: .needMoreBytes)
        }

        byteBuffer.moveReaderIndex(forwardBy: 1)

        guard let method = Method.init(rawValue: byteBuffer.readInteger()!) else {
            throw SOCKS5ProxyError.serializeFailed(reason: .invalidInputBytes)
        }

        self.method = method

        guard method != .noAuth else {
            writeRELMsg(context: context)
            return
        }

        writeAMsg(context: context)
    }

    public override func writeAMsg(context: ChannelHandlerContext) {

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

    public override func recvAMsg(context: ChannelHandlerContext, byteBuffer: inout ByteBuffer) throws {

        switch method {
        case .noAuth:
            assertionFailure("This should never happen.")
        case .basicAuth:
            try recvBasicAMsg(context: context, byteBuffer: &byteBuffer)
            writeRELMsg(context: context)
        default:
            // TODO: - METHOD specific negotation implemention.
            assertionFailure("METHOD specific negotiation not implemented.")
        }
    }

    override public func writeRELMsg(context: ChannelHandlerContext) {
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
        // o  CONNECT X'01'
        // o  BIND X'02'
        // o  UDP ASSOCIATE X'03'
        // o  RSV    RESERVED
        // o  ATYP   address type of following address
        // o  IP V4 address: X'01'
        // o  DOMAINNAME: X'03'
        // o  IP V6 address: X'04'
        // o  DST.ADDR       desired destination address
        // o  DST.PORT desired destination port in network octet order
        //
        // The SOCKS server will typically evaluate the request based on source
        // and destination addresses, and return one or more reply messages, as
        // appropriate for the request type.
        var byteBuffer = context.channel.allocator.buffer(capacity: 6)

        byteBuffer.writeInteger(Version.v5.rawValue)
        byteBuffer.writeInteger(CMD.connect.rawValue)
        byteBuffer.writeInteger(SOCKS5_HANDSHAKE_REL_RSV_CODE)

        guard let taskAddress = configuration.taskAddress else {
            assertionFailure("This should never happen.")
            return
        }
        switch taskAddress {
        case .v4(let addr):
            byteBuffer.writeInteger(ATYP.ipv4.rawValue)
            _ = withUnsafeBytes(of: addr.address.sin_addr) {
                byteBuffer.writeBytes($0)
            }
        case .v6(let addr):
            byteBuffer.writeInteger(ATYP.ipv6.rawValue)
            _ = withUnsafeBytes(of: addr.address.sin6_addr) {
                byteBuffer.writeBytes($0)
            }
        default:
            assertionFailure("This should never happen.")
        }

        _ = withUnsafeBytes(of: in_port_t(taskAddress.port!)) {
            byteBuffer.writeBytes($0)
        }

        context.writeAndFlush(wrapOutboundOut(byteBuffer), promise: nil)
    }

    override public func recvRELMsg(context: ChannelHandlerContext, byteBuffer: inout ByteBuffer) throws {
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

        guard byteBuffer.readableBytes >= 4 else {
            throw SOCKS5ProxyError.serializeFailed(reason: .needMoreBytes)
        }

        byteBuffer.moveReaderIndex(forwardBy: 1)
        let REP = Reply.init(rawValue: byteBuffer.readInteger()!)

        guard REP == .some(.succeeded) else {
            throw SOCKS5ProxyError.replyFailed(reason: .withReply(REP))
        }

        byteBuffer.moveReaderIndex(forwardBy: 1)
        guard let family = ATYP.init(rawValue: byteBuffer.readInteger()!) else {
            throw SOCKS5ProxyError.serializeFailed(reason: .invalidInputBytes)
        }

        let readLength: Int32
        let INET_PORTLEN: Int32 = 8

        switch family {
        case .ipv4: readLength = (INET_ADDRSTRLEN + INET_PORTLEN) / 4
        case .ipv6: readLength = (INET6_ADDRSTRLEN + INET_PORTLEN) / 4
        case .domainLength:
            guard byteBuffer.readableBytes >= 1 else {
                throw SOCKS5ProxyError.serializeFailed(reason: .needMoreBytes)
            }

            readLength = byteBuffer.readInteger()! + INET_PORTLEN / 4
        }

        guard byteBuffer.readableBytes >= readLength else {
            throw SOCKS5ProxyError.serializeFailed(reason: .needMoreBytes)
        }

        byteBuffer.moveReaderIndex(forwardBy: Int(readLength))
    }
}

extension SOCKS5ClientProxyHandler: RFC1919 {

    public func writeBasicAMsg(context: ChannelHandlerContext) {
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
        //
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

        let uLength = auth.username.utf8.count
        let pLength = auth.password.utf8.count

        var byteBuffer = context.channel.allocator.buffer(capacity: 2 + uLength + 1 + pLength)

        byteBuffer.writeInteger(SOCKS5_BASIC_AUTH_VERSION)
        byteBuffer.writeInteger(UInt8(uLength))
        byteBuffer.writeString(auth.username)
        byteBuffer.writeInteger(UInt8(pLength))
        byteBuffer.writeString(auth.password)

        context.writeAndFlush(wrapOutboundOut(byteBuffer), promise: nil)
    }

    public func recvBasicAMsg(context: ChannelHandlerContext, byteBuffer: inout ByteBuffer) throws {
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

        guard byteBuffer.readableBytes >= 2 else {
            throw SOCKS5ProxyError.serializeFailed(reason: .needMoreBytes)
        }

        byteBuffer.moveReaderIndex(forwardBy: 1)

        guard byteBuffer.readInteger()! == SOCKS5_BASIC_AUTH_SUCCESS_CODE else {
            throw SOCKS5ProxyError.authenticationFailed(reason: .incorrectUsernameOrPassword)
        }
    }
}
