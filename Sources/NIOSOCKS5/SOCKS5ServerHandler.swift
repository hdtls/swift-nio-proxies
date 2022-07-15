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

import Logging
import NIOCore

/// Add this handshake handler to the front of your channel, closest to the network.
/// The handler will receive bytes from the network and run them through a state machine
/// and parser to enforce SOCKSv5 protocol correctness. Inbound bytes will by parsed into
/// `ClientMessage` for downstream consumption. Send `ServerMessage` to this
/// handler.
public final class SOCKS5ServerHandler: ChannelDuplexHandler, RemovableChannelHandler {

    public typealias InboundIn = ByteBuffer
    public typealias InboundOut = ByteBuffer
    public typealias OutboundIn = ByteBuffer
    public typealias OutboundOut = ByteBuffer

    private var state: HandshakeState
    private var inboundBuffer: ByteBuffer!
    private var bufferedWrites: MarkedCircularBuffer<BufferedWrite> = .init(initialCapacity: 8)
    private let logger: Logger
    private let username: String
    private let passwordReference: String
    private let authenticationRequired: Bool

    public init(
        logger: Logger,
        username: String,
        passwordReference: String,
        authenticationRequired: Bool,
        completion: @escaping (NetAddress) -> EventLoopFuture<Channel>
    ) {
        self.logger = logger
        self.username = username
        self.passwordReference = passwordReference
        self.authenticationRequired = authenticationRequired
        self.state = .idle
    }

    public func handlerAdded(context: ChannelHandlerContext) {
        startHandshaking(context: context)
    }

    public func channelActive(context: ChannelHandlerContext) {
        startHandshaking(context: context)
        context.fireChannelActive()
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var byteBuffer = unwrapInboundIn(data)

        guard !state.isActive else {
            context.fireChannelRead(wrapInboundOut(byteBuffer))
            return
        }

        inboundBuffer.setOrWriteBuffer(&byteBuffer)

        do {
            switch state {
                case .greeting:
                    try evaluateClientGreeting(context: context)
                case .authorizing:
                    try evaluateClientAuthenticationMsg(context: context)
                case .addressing:
                    try evaluateClientRequestAndReplies(context: context)
                default:
                    break
            }
        } catch {
            deliverOneError(error, context: context)
        }
    }

    public func write(
        context: ChannelHandlerContext,
        data: NIOAny,
        promise: EventLoopPromise<Void>?
    ) {
        bufferWrite(data: unwrapOutboundIn(data), promise: promise)
    }

    public func flush(context: ChannelHandlerContext) {
        bufferFlush()

        guard state.isActive else {
            return
        }
        unbufferWrites(context: context)
    }
}

extension SOCKS5ServerHandler {

    private typealias BufferedWrite = (data: ByteBuffer, promise: EventLoopPromise<Void>?)

    private func bufferWrite(data: ByteBuffer, promise: EventLoopPromise<Void>?) {
        bufferedWrites.append((data: data, promise: promise))
    }

    private func bufferFlush() {
        bufferedWrites.mark()
    }

    private func unbufferWrites(context: ChannelHandlerContext) {
        // Return early if the user hasn't called flush.
        guard bufferedWrites.hasMark else {
            return
        }

        while bufferedWrites.hasMark {
            let bufferedWrite = bufferedWrites.removeFirst()
            context.write(wrapOutboundOut(bufferedWrite.data), promise: bufferedWrite.promise)
        }
        context.flush()
    }
}

extension SOCKS5ServerHandler {

    private func startHandshaking(context: ChannelHandlerContext) {
        guard context.channel.isActive else {
            return
        }
        do {
            try state.idle()
        } catch {
            deliverOneError(error, context: context)
        }
    }

    private func evaluateClientGreeting(context: ChannelHandlerContext) throws {
        guard let clientGreeting = try inboundBuffer.readAuthenticationMethodRequest() else {
            return
        }

        // Choose authentication method
        let method: Authentication.Method.Response

        if authenticationRequired && clientGreeting.methods.contains(.usernamePassword) {
            method = .init(method: .usernamePassword)
            try state.greeting(.usernamePassword)
        } else if clientGreeting.methods.contains(.noRequired) {
            method = .init(method: .noRequired)
            try state.greeting(.noRequired)
        } else {
            method = .init(method: .noAcceptable)
            // TODO: Error handling NO acceptable method.
            state.failure()
        }

        var buffer = context.channel.allocator.buffer(capacity: 2)
        buffer.writeAuthenticationMethodResponse(method)

        context.writeAndFlush(wrapOutboundOut(buffer), promise: nil)
    }

    private func evaluateClientAuthenticationMsg(context: ChannelHandlerContext) throws {
        guard let authMsg = try inboundBuffer.readAuthenticationRequest() else {
            // Need more bytes to parse authentication message.
            return
        }

        try state.authorizing()

        let success =
            authMsg.username == username && authMsg.password == passwordReference

        var buffer = context.channel.allocator.buffer(capacity: 2)
        buffer.writeAuthenticationResponse(
            Authentication.UsernameAuthenticationResponse(status: success ? 0 : 1)
        )

        context.writeAndFlush(wrapOutboundOut(buffer), promise: nil)
    }

    private func evaluateClientRequestAndReplies(context: ChannelHandlerContext) throws {
        guard let request = try inboundBuffer.readRequestDetails() else { return }

        let completion: (NetAddress) -> EventLoopFuture<Channel> = { _ in
            context.eventLoop.makeCompletedFuture(.failure(SOCKSError.unexpectedRead))
        }

        let client = completion(request.address)

        logger.info("connecting to proxy server...")

        client.whenSuccess { channel in
            self.handleGlue(peer: channel, context: context)
        }

        client.whenFailure { error in
            self.state.failure()

            // TODO: Fix reply
            let response: Response = .init(reply: .hostUnreachable, boundAddress: request.address)

            var buffer = context.channel.allocator.buffer(capacity: 16)
            buffer.writeServerResponse(response)

            context.writeAndFlush(self.wrapOutboundOut(buffer), promise: nil)

            self.deliverOneError(error, context: context)
        }
    }

    private func handleGlue(peer: Channel, context: ChannelHandlerContext) {
        logger.info("proxy server connected \(peer.remoteAddress!)")

        let response: Response = .init(
            reply: .succeeded,
            boundAddress: .socketAddress(peer.remoteAddress!)
        )

        do {
            try state.establish()
        } catch {
            deliverOneError(error, context: context)
        }

        context.fireUserInboundEventTriggered(SOCKSProxyEstablishedEvent())

        var buffer = context.channel.allocator.buffer(capacity: 16)
        buffer.writeServerResponse(response)

        context.writeAndFlush(wrapOutboundOut(buffer), promise: nil)

        let (localGlue, peerGlue) = GlueHandler.matchedPair()

        // Now we need to glue our channel and the peer channel together.
        context.channel.pipeline.addHandler(localGlue)
            .and(peer.pipeline.addHandler(peerGlue))
            .flatMap { _ in
                context.pipeline.removeHandler(self)
            }
            .flatMap {
                context.eventLoop.makeSucceededFuture(self.unbufferWrites(context: context))
            }
            .whenFailure { error in
                // Close connected peer channel before closing our channel.
                peer.close(promise: nil)
                self.deliverOneError(error, context: context)
            }
    }

    private func deliverOneError(_ error: Error, context: ChannelHandlerContext) {

    }
}
