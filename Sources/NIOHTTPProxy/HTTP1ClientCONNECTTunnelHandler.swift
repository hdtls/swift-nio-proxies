//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2021 Junfeng Zhang. and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore

final public class HTTP1ClientCONNECTTunnelHandler: ChannelDuplexHandler, RemovableChannelHandler {

    public typealias InboundIn = HTTPClientResponsePart
    public typealias OutboundIn = NIOAny

    /// The usename used to authenticate this proxy connection.
    private let username: String

    /// The password used to authenticate this proxy connection.
    private let passwordReference: String

    /// A boolean value deterinse whether client should perform proxy authentication.
    private let authenticationRequired: Bool

    /// A boolean value determinse whether client should use HTTP CONNECT tunnel to proxy connection.
    private let preferHTTPTunneling: Bool

    /// The destination for this proxy connection.
    private let destinationAddress: NetAddress
    private var state: ConnectionState
    private var headPart: HTTPResponseHead?

    /// The circular buffer to buffer channel write before handshake established.
    ///
    /// All buffered write will unbuffered when proxy established.
    private var bufferedWrites: MarkedCircularBuffer<BufferedWrite>

    /// Initialize an instance of `HTTP1ClientCONNECTTunnelHandler` with specified parameters.
    ///
    /// - Parameters:
    ///   - username: Username for proxy authentication.
    ///   - passwordReference: Password for proxy authentication.
    ///   - authenticationRequired: A boolean value deterinse whether client should perform proxy authentication.
    ///   - preferHTTPTunneling: A boolean value determinse whether client should use HTTP CONNECT tunnel to proxy connection.
    ///   - destinationAddress: The destination for this proxy connection.
    public init(
        username: String,
        passwordReference: String,
        authenticationRequired: Bool,
        preferHTTPTunneling: Bool,
        destinationAddress: NetAddress
    ) {
        self.username = username
        self.passwordReference = passwordReference
        self.authenticationRequired = authenticationRequired
        self.preferHTTPTunneling = preferHTTPTunneling
        self.destinationAddress = destinationAddress
        self.state = .idle
        self.bufferedWrites = .init(initialCapacity: 6)
    }

    public func handlerAdded(context: ChannelHandlerContext) {
        if context.channel.isActive {
            performCONNECTHandshake(context: context)
        }
    }

    public func channelActive(context: ChannelHandlerContext) {
        context.fireChannelActive()
        performCONNECTHandshake(context: context)
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard state != .active else {
            context.fireChannelRead(data)
            return
        }

        switch unwrapInboundIn(data) {
            case .head(let head) where state == .handshaking:
                headPart = head
            case .end where state == .handshaking && headPart != nil:
                established(context: context)
            default:
                context.fireErrorCaught(HTTPProxyError.invalidHTTPOrdering)
                channelClose(context: context, reason: HTTPProxyError.invalidHTTPOrdering)
        }
    }

    public func write(
        context: ChannelHandlerContext,
        data: NIOAny,
        promise: EventLoopPromise<Void>?
    ) {
        bufferedWrites.append((data, promise))
    }

    public func flush(context: ChannelHandlerContext) {
        bufferedWrites.mark()

        // Unbuffer writes when handshake is success.
        guard state == .active else {
            return
        }
        unbufferWrites(context: context)
    }
}

extension HTTP1ClientCONNECTTunnelHandler {

    private typealias BufferedWrite = (data: NIOAny, promise: EventLoopPromise<Void>?)

    private func unbufferWrites(context: ChannelHandlerContext) {
        while bufferedWrites.hasMark {
            let bufferedWrite = bufferedWrites.removeFirst()
            context.write(bufferedWrite.data, promise: bufferedWrite.promise)
        }
        context.flush()

        while !bufferedWrites.isEmpty {
            let bufferedWrite = bufferedWrites.removeFirst()
            context.write(bufferedWrite.data, promise: bufferedWrite.promise)
        }
    }
}

extension HTTP1ClientCONNECTTunnelHandler {

    private func performCONNECTHandshake(context: ChannelHandlerContext) {
        guard context.channel.isActive, state == .idle else {
            return
        }

        state = .handshaking

        let uri: String
        switch destinationAddress {
            case .domainPort(let domain, let port):
                uri = "\(domain):\(port)"
            case .socketAddress(let socketAddress):
                guard let host = socketAddress.ipAddress else {
                    context.fireErrorCaught(HTTPProxyError.invalidURL(url: "nil"))
                    channelClose(context: context, reason: HTTPProxyError.invalidURL(url: "nil"))
                    return
                }
                uri = "\(host):\(socketAddress.port ?? 80)"
        }

        var head: HTTPRequestHead = .init(version: .http1_1, method: .CONNECT, uri: uri)
        if authenticationRequired {
            head.headers.proxyBasicAuthorization = .init(
                username: username,
                password: passwordReference
            )
        }

        context.write(NIOAny(HTTPClientRequestPart.head(head)), promise: nil)
        context.writeAndFlush(NIOAny(HTTPClientRequestPart.end(nil)), promise: nil)
    }

    private func established(context: ChannelHandlerContext) {
        context.pipeline.handler(type: HTTPRequestEncoder.self)
            .flatMap {
                context.pipeline.removeHandler($0)
            }
            .flatMap {
                context.pipeline.handler(type: ByteToMessageHandler<HTTPResponseDecoder>.self)
            }
            .flatMap {
                context.pipeline.removeHandler($0)
            }
            .whenComplete {
                switch $0 {
                    case .success:
                        self.state = .active
                        self.unbufferWrites(context: context)
                        context.fireUserInboundEventTriggered(
                            UserEvent.established(channel: context.channel)
                        )
                        context.pipeline.removeHandler(self, promise: nil)
                    case .failure(let error):
                        context.fireErrorCaught(error)
                        self.channelClose(context: context, reason: error)
                }
            }
    }

    private func channelClose(context: ChannelHandlerContext, reason: Error) {
        context.close(promise: nil)
    }
}
