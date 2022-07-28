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
import NIONetbotMisc

/// Add this handshake handler to the front of your channel, closest to the network.
/// The handler will receive bytes from the network and run them through a state machine
/// and parser to enforce SOCKSv5 protocol correctness. Inbound bytes will by parsed into
/// `ClientMessage` for downstream consumption. Send `ServerMessage` to this
/// handler.
final public class SOCKS5ServerHandler: ChannelDuplexHandler, RemovableChannelHandler {

    public typealias InboundIn = ByteBuffer
    public typealias InboundOut = ByteBuffer
    public typealias OutboundIn = ByteBuffer
    public typealias OutboundOut = ByteBuffer

    private var state: HandshakeState
    private var readBuffer: ByteBuffer!
    private var bufferedWrites: MarkedCircularBuffer<BufferedWrite> = .init(initialCapacity: 8)
    private var removalToken: ChannelHandlerContext.RemovalToken?
    private let logger: Logger
    private let username: String
    private let passwordReference: String
    private let authenticationRequired: Bool
    private var channelInitializer: (NetAddress) -> EventLoopFuture<Channel>

    public init(
        logger: Logger,
        username: String,
        passwordReference: String,
        authenticationRequired: Bool,
        channelInitializer: @escaping (NetAddress) -> EventLoopFuture<Channel>
    ) {
        self.logger = logger
        self.username = username
        self.passwordReference = passwordReference
        self.authenticationRequired = authenticationRequired
        self.state = .greeting
        self.channelInitializer = channelInitializer
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var byteBuffer = unwrapInboundIn(data)

        guard state != .established else {
            context.fireChannelRead(data)
            return
        }

        readBuffer.setOrWriteBuffer(&byteBuffer)

        switch state {
            case .greeting:
                receiveAuthenticationMethodRequest(context: context)
            case .authorizing:
                receiveAuthenticationRequest(context: context)
            case .addressing:
                evaluateClientRequestAndReplies(context: context)
            default:
                break
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

        guard state == .established else {
            return
        }
        unbufferWrites(context: context)
    }

    public func removeHandler(
        context: ChannelHandlerContext,
        removalToken: ChannelHandlerContext.RemovalToken
    ) {
        precondition(context.handler === self)

        guard state == .established else {
            self.removalToken = removalToken
            return
        }

        flushBuffers(context: context)

        context.leavePipeline(removalToken: removalToken)
    }
}

extension SOCKS5ServerHandler {

    private typealias BufferedWrite = (data: ByteBuffer, promise: EventLoopPromise<Void>?)

    private func bufferWrite(data: ByteBuffer, promise: EventLoopPromise<Void>?) {
        guard data.readableBytes > 0 else {
            // We don't care about empty buffer.
            return
        }
        bufferedWrites.append((data: data, promise: promise))
    }

    private func bufferFlush() {
        bufferedWrites.mark()
    }

    private func unbufferWrites(context: ChannelHandlerContext) {
        while bufferedWrites.hasMark {
            let bufferedWrite = bufferedWrites.removeFirst()
            context.write(wrapOutboundOut(bufferedWrite.data), promise: bufferedWrite.promise)
        }
        context.flush()

        while !bufferedWrites.isEmpty {
            let bufferedWrite = bufferedWrites.removeFirst()
            context.write(wrapOutboundOut(bufferedWrite.data), promise: bufferedWrite.promise)
        }
    }

    private func flushBuffers(context: ChannelHandlerContext) {
        unbufferWrites(context: context)

        if let byteBuffer = readBuffer, byteBuffer.readableBytes > 0 {
            readBuffer = nil
            context.fireChannelRead(wrapInboundOut(byteBuffer))
        }
    }

}

extension SOCKS5ServerHandler {

    private func receiveAuthenticationMethodRequest(context: ChannelHandlerContext) {
        guard let req = readBuffer.readAuthenticationMethodRequest() else {
            return
        }

        guard req.version == .v5 else {
            context.fireErrorCaught(SOCKSError.unsupportedProtocolVersion)
            channelClose(context: context, reason: SOCKSError.unsupportedProtocolVersion)
            return
        }

        // Choose authentication method
        let response: Authentication.Method.Response

        if authenticationRequired && req.methods.contains(.usernamePassword) {
            response = .init(method: .usernamePassword)
            state = .authorizing
        } else if req.methods.contains(.noRequired) {
            response = .init(method: .noRequired)
            state = .addressing
        } else {
            response = .init(method: .noAcceptable)
            // TODO: Error handling NO acceptable method.
        }

        var buffer = context.channel.allocator.buffer(capacity: 2)
        buffer.writeAuthenticationMethodResponse(response)

        context.writeAndFlush(wrapOutboundOut(buffer), promise: nil)
    }

    private func receiveAuthenticationRequest(context: ChannelHandlerContext) {
        guard let authMsg = readBuffer.readAuthenticationRequest() else {
            // Need more bytes to parse authentication message.
            return
        }

        state = .addressing

        let success = authMsg.username == username && authMsg.password == passwordReference

        var buffer = context.channel.allocator.buffer(capacity: 2)
        buffer.writeAuthenticationResponse(
            Authentication.UsernameAuthenticationResponse(status: success ? 0 : 1)
        )

        context.writeAndFlush(wrapOutboundOut(buffer), promise: nil)

        // If authentication failure then channel MUST close.
        // https://datatracker.ietf.org/doc/html/rfc1929#section-2
        guard !success else {
            return
        }
        context.close(promise: nil)
    }

    private func evaluateClientRequestAndReplies(context: ChannelHandlerContext) {
        precondition(state == .addressing)
        let req: Request?

        do {
            req = try readBuffer.readRequestDetails()
        } catch {
            context.fireErrorCaught(error)
            channelClose(context: context, reason: error)
            return
        }

        guard let req = req else {
            return
        }

        channelInitializer(req.address).whenComplete {
            switch $0 {
                case .success(let channel):
                    self.exchange(channel, context: context, userInfo: req)
                case .failure:
                    let response: Response = .init(
                        reply: .hostUnreachable,
                        boundAddress: req.address
                    )

                    var buffer = context.channel.allocator.buffer(capacity: 16)
                    buffer.writeServerResponse(response)

                    context.writeAndFlush(self.wrapOutboundOut(buffer), promise: nil)
            }
        }
    }

    private func exchange(_ channel: Channel, context: ChannelHandlerContext, userInfo: Request) {
        logger.info(
            "Tunneling request to \(userInfo.address) via \(String(describing: channel.remoteAddress))"
        )

        let response = Response(
            reply: .succeeded,
            boundAddress: .socketAddress(channel.remoteAddress!)
        )

        var buffer = context.channel.allocator.buffer(capacity: 16)
        buffer.writeServerResponse(response)

        context.writeAndFlush(wrapOutboundOut(buffer), promise: nil)

        state = .established

        let (localGlue, peerGlue) = GlueHandler.matchedPair()

        // Now we need to glue our channel and the peer channel together.
        context.channel.pipeline.addHandler(localGlue)
            .and(channel.pipeline.addHandler(peerGlue))
            .whenComplete {
                switch $0 {
                    case .success:
                        self.flushBuffers(context: context)

                        context.fireUserInboundEventTriggered(SOCKSUserEvent.handshakeCompleted)

                        if let removalToken = self.removalToken {
                            context.leavePipeline(removalToken: removalToken)
                        }
                    case .failure(let error):
                        context.fireErrorCaught(error)
                        self.channelClose(context: context, reason: error)
                }
            }
    }

    private func channelClose(context: ChannelHandlerContext, reason: Error) {
        logger.error("\(reason)")
        context.close(promise: nil)
    }
}
