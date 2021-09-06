//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2021 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

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

import NIO
import Helpers

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
    
    private let targetAddress: NetAddress
    
    private var state: ClientStateMachine
    private var removalToken: ChannelHandlerContext.RemovalToken?
    private var inboundBuffer: ByteBuffer?
    
    private var bufferedWrites: MarkedCircularBuffer<(NIOAny, EventLoopPromise<Void>?)> = .init(initialCapacity: 8)
    
    private let credential: Credential?
    
    /// Creates a new `SOCKS5ClientHandler` that connects to a server
    /// and instructs the server to connect to `targetAddress`.
    /// - parameter targetAddress: The desired end point - note that only IPv4, IPv6, and FQDNs are supported.
    public init(credential: Credential? = nil, targetAddress: NetAddress) {
        
        switch targetAddress {
            case .socketAddress(.unixDomainSocket):
                preconditionFailure("UNIX domain sockets are not supported.")
            case .domainPort, .socketAddress(.v4), .socketAddress(.v6):
                break
        }
        
        self.state = ClientStateMachine()
        self.credential = credential
        self.targetAddress = targetAddress
    }
    
    public func channelActive(context: ChannelHandlerContext) {
        beginHandshake(context: context)
    }
    
    public func handlerAdded(context: ChannelHandlerContext) {
        beginHandshake(context: context)
    }
    
    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        
        // if we've established the connection then forward on the data
        if state.proxyEstablished {
            context.fireChannelRead(data)
            return
        }
        
        var inboundBuffer = unwrapInboundIn(data)
        
        self.inboundBuffer.setOrWriteBuffer(&inboundBuffer)
        do {
            // Safe to bang, `setOrWrite` above means there will
            // always be a value.
            let action = try state.receiveBuffer(&self.inboundBuffer!)
            try handleAction(action, context: context)
        } catch {
            context.fireErrorCaught(error)
            context.close(promise: nil)
        }
    }
    
    public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        if state.proxyEstablished && bufferedWrites.count == 0 {
            context.write(data, promise: promise)
        } else {
            bufferedWrites.append((data, promise))
        }
    }
    
    private func writeBufferedData(context: ChannelHandlerContext) {
        guard state.proxyEstablished else {
            return
        }
        while bufferedWrites.hasMark {
            let (data, promise) = bufferedWrites.removeFirst()
            context.write(data, promise: promise)
        }
        // safe to flush otherwise we wouldn't have the mark
        context.flush()
        
        while !bufferedWrites.isEmpty {
            let (data, promise) = bufferedWrites.removeFirst()
            context.write(data, promise: promise)
        }
    }
    
    public func flush(context: ChannelHandlerContext) {
        bufferedWrites.mark()
        writeBufferedData(context: context)
    }
    
    public func removeHandler(context: ChannelHandlerContext, removalToken: ChannelHandlerContext.RemovalToken) {
        guard state.proxyEstablished else {
            self.removalToken = removalToken
            return
        }
        
        // We must clear the buffers here before we are removed, since the
        // handler removal may be triggered as a side effect of the
        // `SOCKSProxyEstablishedEvent`. In this case we may end up here,
        // before the buffer empty method in `handleProxyEstablished` is
        // invoked.
        emptyInboundAndOutboundBuffer(context: context)
        context.leavePipeline(removalToken: removalToken)
    }
}

extension SOCKS5ClientHandler {
    
    private func beginHandshake(context: ChannelHandlerContext) {
        guard context.channel.isActive, state.shouldBeginHandshake else {
            return
        }
        do {
            try handleAction(state.connectionEstablished(), context: context)
        } catch {
            context.fireErrorCaught(error)
            context.close(promise: nil)
        }
    }
    
    private func handleAction(_ action: ClientAction, context: ChannelHandlerContext) throws {
        switch action {
            case .waitForMoreData:
                break // do nothing, we've already buffered the data
            case .sendGreeting:
                try sendClientGreeting(context: context)
            case .sendAuthentication:
                try sendUsernamePasswordAuthentication(context: context)
            case .sendRequest:
                try sendClientRequest(context: context)
            case .proxyEstablished:
                handleProxyEstablished(context: context)
        }
    }
    
    private func sendClientGreeting(context: ChannelHandlerContext) throws {
        let greeting = ClientGreeting(methods: [
            credential == nil ? .noRequired : .usernamePassword
        ]) // no authentication currently supported
        let capacity = 3 // [version, #methods, methods...]
        var buffer = context.channel.allocator.buffer(capacity: capacity)
        buffer.writeClientGreeting(greeting)
        try state.sendClientGreeting(greeting)
        context.writeAndFlush(wrapOutboundOut(buffer), promise: nil)
    }
    
    private func handleProxyEstablished(context: ChannelHandlerContext) {
        context.fireUserInboundEventTriggered(SOCKSProxyEstablishedEvent())
        
        context.pipeline.removeHandler(context: context, promise: nil)
    }
    
    private func sendUsernamePasswordAuthentication(context: ChannelHandlerContext) throws {
        guard let credential = credential else {
            throw SOCKSError.missingCredential
        }
        let authentication = UsernamePasswordAuthentication(username: credential.identity, password: credential.identityTokenString)
        let capacity = 3 + credential.identity.count + credential.identityTokenString.count
        var byteBuffer = context.channel.allocator.buffer(capacity: capacity)
        byteBuffer.writeUsernamePasswordAuthentication(authentication)
        try state.sendClientAuthentication(authentication)
        context.writeAndFlush(wrapOutboundOut(byteBuffer), promise: nil)
    }
    
    private func sendClientRequest(context: ChannelHandlerContext) throws {
        let request = Request(command: .connect, address: targetAddress)
        try state.sendClientRequest(request)
        
        // the client request is always 6 bytes + the address info
        // [protocol_version, command, reserved, address type, <address>, port (2bytes)]
        let capacity: Int
        switch targetAddress {
            case .domainPort(let domain, _):
                capacity = 6 + domain.utf8.count + 1
            case .socketAddress(let addr):
                switch addr {
                    case .v4:
                        capacity = 6 + 4
                    case .v6:
                        capacity = 6 + 16
                    case .unixDomainSocket:
                        capacity = 0
                        fatalError("Unsupported")
                }
        }
        var buffer = context.channel.allocator.buffer(capacity: capacity)
        buffer.writeClientRequest(request)
        context.writeAndFlush(wrapOutboundOut(buffer), promise: nil)
    }
    
    private func emptyInboundAndOutboundBuffer(context: ChannelHandlerContext) {
        if let inboundBuffer = inboundBuffer, inboundBuffer.readableBytes > 0 {
            // after the SOCKS handshake message we already received further bytes.
            // so let's send them down the pipe
            self.inboundBuffer = nil
            context.fireChannelRead(wrapInboundOut(inboundBuffer))
        }
        
        // If we have any buffered writes, we must send them before we are removed from the pipeline
        writeBufferedData(context: context)
    }
    
}

/// A `Channel` user event that is sent when a SOCKS connection has been established
///
/// After this event has been received it is save to remove the `SOCKS5ClientHandler` from the channel pipeline.
public struct SOCKSProxyEstablishedEvent {
    public init() {}
}
