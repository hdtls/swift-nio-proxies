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
import NIOSecurity

/// HTTP/HTTPS obfuscating options.
public enum Obfuscating: Equatable {
    case off
    case http(String)
    case https(String)
}

/// Shadowsocks Proxy configuation
public struct ProxyConfiguration: Equatable {

    /// Authentication password.
    public var password: String

    /// Security ALGO.
    public var algorithm: Algorithm

    /// Allow UDP relay.
    public var allowUDPRelay: Bool

    /// TCP fast open.
    public var tcpFastOpen: Bool

    /// Allow HTTP/HTTPS to obfuscate data transfer.
    public var obfuscating: Obfuscating

    public init(password: String,
                algorithm: Algorithm,
                allowUDPRelay: Bool = false,
                tcpFastOpen: Bool = false,
                obfuscating: Obfuscating = .off) {
        self.password = password
        self.algorithm = algorithm
        self.allowUDPRelay = allowUDPRelay
        self.tcpFastOpen = tcpFastOpen
        self.obfuscating = obfuscating
    }
}

public final class ShadowsocksClientProxyHandler: ChannelDuplexHandler {

    public typealias InboundIn = ByteBuffer
    public typealias InboundOut = ByteBuffer
    public typealias OutboundIn = ByteBuffer
    public typealias OutboundOut = ByteBuffer

    /// Shadowsocks security encipher.
    private let encipher: Cryptor & Updatable

    /// Shadowsocks security decipher.
    private let decipher: Cryptor & Updatable

    /// A identifier use to determine whether this is the first time to send data.
    private var isHEAD: Bool = true

    public let configuration: ProxyConfiguration

    public init(configuration: ProxyConfiguration) throws {
        self.configuration = configuration
        let security: Security = .init(algorithm: configuration.algorithm, key: EVP_BytesToKey(configuration.algorithm, pwd: configuration.password))
        self.encipher = try security.makeEncryptor()
        self.decipher = try security.makeDecryptor()
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var unwrapped = unwrapInboundIn(data)

        guard let buf = unwrapped.readBytes(length: unwrapped.readableBytes) else {
            context.fireChannelRead(data)
            return
        }

        do {
            var byteBuffer = context.channel.allocator.buffer(capacity: buf.count)
            byteBuffer.writeBytes(try decipher.update(buf))

            context.fireChannelRead(wrapInboundOut(byteBuffer))
        } catch {
            context.fireErrorCaught(error)
        }
    }

    public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        var unwrapped = unwrapOutboundIn(data)

        guard var buf = unwrapped.readBytes(length: unwrapped.readableBytes) else {
            context.write(data, promise: promise)
            return
        }

        do {
            if isHEAD {
                // Addresses used in Shadowsocks follow the SOCKS5 address format:
                // [1-byte type][variable-length host][2-byte port]
                // The following address types are defined:
                //  0x01: host is a 4-byte IPv4 address.
                //  0x03: host is a variable length string, starting with a 1-byte length, followed by up to 255-byte domain name.
                //  0x04: host is a 16-byte IPv6 address.
                // The port number is a 2-byte big-endian unsigned integer.

                // TODO: Add destination address.
                buf.insert(contentsOf: [], at: 0)
                isHEAD = false
            }

            var byteBuffer = context.channel.allocator.buffer(capacity: buf.count)

            byteBuffer.writeBytes(try encipher.update(buf))
            context.write(wrapOutboundOut(byteBuffer), promise: promise)
        } catch {
            promise?.fail(error)
        }
    }
}
