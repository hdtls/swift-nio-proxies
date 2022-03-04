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

import NetbotCore
import NIOCore

/// Credential use for username and password authentication.
public struct Credential {
    
    public let identity: String
    public let identityTokenString: String
    
    public init(identity: String, identityTokenString: String) {
        self.identity = identity
        self.identityTokenString = identityTokenString
    }
}

/// Connects to a SOCKS server to establish a proxied connection
/// to a host. This handler should be inserted at the beginning of a
/// channel's pipeline. Note that SOCKS only supports fully-qualified
/// domain names and IPv4 or IPv6 sockets, and not UNIX sockets.
public final class SOCKS5ClientHandler: ChannelDuplexHandler, RemovableChannelHandler {
    
    public typealias InboundIn = ByteBuffer
    public typealias InboundOut = ByteBuffer
    public typealias OutboundIn = ByteBuffer
    public typealias OutboundOut = ByteBuffer
    
    private var state: HandshakeState
    private var readBuffer: ByteBuffer!
    private var bufferedWrites: MarkedCircularBuffer<BufferedWrite>
    
    public let logger: Logger
    public let credential: Credential?
    public let targetAddress: NetAddress
    
    /// Creates a new `SOCKS5ClientHandler` that connects to a server
    /// and instructs the server to connect to `targetAddress`.
    /// - parameter targetAddress: The desired end point - note that only IPv4, IPv6, and FQDNs are supported.
    public init(logger: Logger = .init(label: "com.netbot.socks"), credential: Credential? = nil, targetAddress: NetAddress) {
        switch targetAddress {
            case .socketAddress(.unixDomainSocket):
                preconditionFailure("UNIX domain sockets are not supported.")
            case .domainPort, .socketAddress(.v4), .socketAddress(.v6):
                break
        }
        
        self.logger = logger
        self.credential = credential
        self.targetAddress = targetAddress
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
                    try evaluateServerGreeting(context: context)
                case .authorizing:
                    try evaluateServerAuthenticationMsg(context: context)
                case .addressing:
                    try evaluateServerReplies(context: context)
                default:
                    break
            }
        } catch {
            deliverOneError(error, context: context)
        }
    }
    
    public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
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
            try sendClientGreeting(context: context)
        } catch {
            deliverOneError(error, context: context)
        }
    }
    
    private func sendClientGreeting(context: ChannelHandlerContext) throws {
        
        let method: AuthenticationMethod = credential == nil ? .noRequired : .usernamePassword
        
        let greeting = ClientGreeting(methods: [method])
        
        // [version, #methods, methods...]
        let capacity = 3
        var buffer = context.channel.allocator.buffer(capacity: capacity)
        buffer.writeClientGreeting(greeting)
        
        context.writeAndFlush(wrapOutboundOut(buffer), promise: nil)
    }
    
    private func evaluateServerGreeting(context: ChannelHandlerContext) throws {
        guard let authentication = try readBuffer?.readMethodSelectionIfPossible() else {
            return
        }
        
        try state.greeting(authentication.method)
        
        switch authentication.method {
            case .noRequired:
                try sendClientRequest(context: context)
            case .usernamePassword:
                try sendUsernamePasswordAuthentication(context: context)
            case .noAcceptable:
                state.failure()
                throw SOCKSError.authenticationFailed(reason: .noValidAuthenticationMethod)
            default:
                state.failure()
                throw SOCKSError.authenticationFailed(reason: .noMethodImpl)
        }
    }
    
    private func evaluateServerAuthenticationMsg(context: ChannelHandlerContext) throws {
        guard let authMsg = try readBuffer?.readUsernamePasswordAuthenticationResponse() else {
            return
        }
        
        try state.authorizing()
        
        guard authMsg.isSuccess else {
            state.failure()
            throw SOCKSError.authenticationFailed(reason: .incorrectUsernameOrPassword)
        }
        
        try sendClientRequest(context: context)
    }
    
    private func sendUsernamePasswordAuthentication(context: ChannelHandlerContext) throws {
        guard let credential = credential else {
            throw SOCKSError.missingCredential
        }
        
        let authentication = UsernamePasswordAuthentication(username: credential.identity, password: credential.identityTokenString)
        
        let capacity = 3 + credential.identity.count + credential.identityTokenString.count
        var byteBuffer = context.channel.allocator.buffer(capacity: capacity)
        byteBuffer.writeUsernamePasswordAuthentication(authentication)
        
        context.writeAndFlush(wrapOutboundOut(byteBuffer), promise: nil)
    }
    
    private func sendClientRequest(context: ChannelHandlerContext) throws {
        let request = Request(command: .connect, address: targetAddress)
        
        // the client request is always 6 bytes + the address info
        // [protocol_version, command, reserved, address type, <address>, port (2bytes)]
        let capacity = 6
        var buffer = context.channel.allocator.buffer(capacity: capacity)
        buffer.writeClientRequest(request)
        context.writeAndFlush(wrapOutboundOut(buffer), promise: nil)
    }
    
    private func evaluateServerReplies(context: ChannelHandlerContext) throws {
        guard let response = try readBuffer?.readServerResponseIfPossible() else {
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
