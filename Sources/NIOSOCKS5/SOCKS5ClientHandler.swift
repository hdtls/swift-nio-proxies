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

/// Connects to a SOCKS server to establish a proxied connection
/// to a host. This handler should be inserted at the beginning of a
/// channel's pipeline. Note that SOCKS only supports fully-qualified
/// domain names and IPv4 or IPv6 sockets, and not UNIX sockets.
final public class SOCKS5ClientHandler: ChannelDuplexHandler, RemovableChannelHandler {

    public typealias InboundIn = ByteBuffer
    public typealias InboundOut = ByteBuffer
    public typealias OutboundIn = ByteBuffer
    public typealias OutboundOut = ByteBuffer

    private var state: HandshakeState
    private var readBuffer: ByteBuffer!
    private var bufferedWrites: MarkedCircularBuffer<BufferedWrite>
    private let logger: Logger
    private let destinationAddress: NetAddress
    private let username: String
    private let passwordReference: String
    private let authenticationRequired: Bool

    /// Creates a new `SOCKS5ClientHandler` that connects to a server
    /// and instructs the server to connect to `destinationAddress`.
    /// - Parameters:
    ///   - logger: logger object use to log message.
    ///   - username: The username for username/password authentication,
    ///   - passwordReference: The password use for username/password authentication.
    ///   - authenticationRequired: A boolean value determinse whether should use username and password authentication.
    ///   - destinationAddress: The desired end point - note that only IPv4, IPv6, and FQDNs are supported.
    public init(
        logger: Logger,
        username: String,
        passwordReference: String,
        authenticationRequired: Bool,
        destinationAddress: NetAddress
    ) {
        switch destinationAddress {
            case .socketAddress(.unixDomainSocket):
                preconditionFailure("UNIX domain sockets are not supported.")
            case .domainPort, .socketAddress(.v4), .socketAddress(.v6):
                break
        }

        self.logger = logger
        self.username = username
        self.passwordReference = passwordReference
        self.authenticationRequired = authenticationRequired
        self.destinationAddress = destinationAddress
        self.state = .idle
        self.bufferedWrites = .init(initialCapacity: 6)
    }

    public func handlerAdded(context: ChannelHandlerContext) {
        startHandshaking(context: context)
    }

    public func channelActive(context: ChannelHandlerContext) {
        startHandshaking(context: context)
        context.fireChannelActive()
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {

        // if we've established the connection then forward on the data
        guard !state.isActive else {
            context.fireChannelRead(data)
            return
        }

        var byteBuffer = unwrapInboundIn(data)

        readBuffer.setOrWriteBuffer(&byteBuffer)

        do {
            switch state {
                case .greeting:
                    try receiveAuthenticationMethodResponse(context: context)
                case .authorizing:
                    try receiveAuthenticationResponse(context: context)
                case .addressing:
                    try receiveReplies(context: context)
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

        // Unbuffer writes when handshake is success.
        guard state.isActive else {
            return
        }
        unbufferWrites(context: context)
    }
}

extension SOCKS5ClientHandler {

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
}

extension SOCKS5ClientHandler {

    private func startHandshaking(context: ChannelHandlerContext) {
        guard context.channel.isActive, state == .idle else {
            return
        }
        do {
            try state.idle()
            try sendAuthenticationMethodRequest(context: context)
        } catch {
            deliverOneError(error, context: context)
        }
    }

    private func sendAuthenticationMethodRequest(context: ChannelHandlerContext) throws {
        // Authorization is performed when `authenticationRequired` is true.
        let method: Authentication.Method = authenticationRequired ? .usernamePassword : .noRequired

        let greeting = Authentication.Method.Request(methods: [method])

        // [version, #methods, methods...]
        let capacity = 3
        var buffer = context.channel.allocator.buffer(capacity: capacity)
        buffer.writeAuthenticationMethodRequest(greeting)

        context.writeAndFlush(wrapOutboundOut(buffer), promise: nil)
    }

    private func receiveAuthenticationMethodResponse(context: ChannelHandlerContext) throws {
        guard let authentication = try readBuffer?.readAuthenticationMethodResponse() else {
            return
        }

        try state.greeting(authentication.method)

        switch authentication.method {
            case .noRequired:
                try sendRequestDetails(context: context)
            case .usernamePassword:
                try sendAuthenticationRequest(context: context)
            case .noAcceptable:
                state.failure()
                throw SOCKSError.authenticationFailed(reason: .noValidAuthenticationMethod)
            default:
                state.failure()
                throw SOCKSError.authenticationFailed(reason: .noMethodImpl)
        }
    }

    private func sendAuthenticationRequest(context: ChannelHandlerContext) throws {
        let authentication = Authentication.UsernameAuthenticationRequest(
            username: username,
            password: passwordReference
        )

        let capacity = 3 + username.count + passwordReference.count
        var byteBuffer = context.channel.allocator.buffer(capacity: capacity)
        byteBuffer.writeAuthenticationRequest(authentication)

        context.writeAndFlush(wrapOutboundOut(byteBuffer), promise: nil)
    }

    private func receiveAuthenticationResponse(context: ChannelHandlerContext) throws {
        guard let authMsg = try readBuffer?.readAuthenticationResponse() else {
            return
        }

        try state.authorizing()

        guard authMsg.isSuccess else {
            state.failure()
            throw SOCKSError.authenticationFailed(reason: .incorrectUsernameOrPassword)
        }

        try sendRequestDetails(context: context)
    }

    private func sendRequestDetails(context: ChannelHandlerContext) throws {
        let request = Request(command: .connect, address: destinationAddress)

        // the client request is always 6 bytes + the address info
        // [protocol_version, command, reserved, address type, <address>, port (2bytes)]
        let capacity = 6
        var buffer = context.channel.allocator.buffer(capacity: capacity)
        buffer.writeRequestDetails(request)
        context.writeAndFlush(wrapOutboundOut(buffer), promise: nil)
    }

    private func receiveReplies(context: ChannelHandlerContext) throws {
        guard let response = try readBuffer?.readServerResponse() else {
            return
        }

        try state.addressing()

        guard response.reply == .succeeded else {
            state.failure()
            throw SOCKSError.replyFailed(reason: .withReply(response.reply))
        }

        // After handshake success we need remove handler and clear buffers.
        unbufferWrites(context: context)

        if let byteBuffer = readBuffer {
            readBuffer.clear()
            context.fireChannelRead(wrapInboundOut(byteBuffer))
        }

        try state.establish()

        context.fireUserInboundEventTriggered(SOCKSProxyEstablishedEvent.init())

        context.pipeline.removeHandler(self, promise: nil)
    }

    private func deliverOneError(_ error: Error, context: ChannelHandlerContext) {
        logger.error("\(error)")
        context.close(promise: nil)
    }
}

/// A `Channel` user event that is sent when a SOCKS connection has been established
///
/// After this event has been received it is save to remove the `SOCKS5ClientHandler` from the channel pipeline.
public struct SOCKSProxyEstablishedEvent {
    public init() {}
}
