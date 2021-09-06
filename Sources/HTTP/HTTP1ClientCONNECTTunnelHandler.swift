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
import NIOHTTP1
import Foundation
import Logging

/// Credential use for username and password authentication.
public struct Credential {
    
    public let identity: String
    public let identityTokenString: String
    
    public init(identity: String, identityTokenString: String) {
        self.identity = identity
        self.identityTokenString = identityTokenString
    }
}

public final class HTTP1ClientCONNECTTunnelHandler: ChannelInboundHandler, RemovableChannelHandler {
    
    public typealias OutboundOut = HTTPClientRequestPart
    public typealias InboundIn = HTTPClientResponsePart
    
    public let logger: Logger
    public let targetAddress: SocketAddress
    public let credential: Credential?
    public let established: EventLoopPromise<Void>?
    
    private var state: ClientStateMachine
    
    public init(logger: Logger = .init(label: "com.netbot.http-client-tunnel"), credential: Credential? = nil,
                targetAddress: SocketAddress,
                established: EventLoopPromise<Void>? = nil) {
        self.logger = logger
        self.credential = credential
        self.targetAddress = targetAddress
        self.established = established
        self.state = ClientStateMachine()
    }
    
    public func handlerAdded(context: ChannelHandlerContext) {
        beginHandshake(context: context)
    }
    
    public func channelActive(context: ChannelHandlerContext) {
        beginHandshake(context: context)
    }
    
    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard !state.proxyEstablished else {
            context.fireChannelRead(data)
            return
        }
        
        do {
            let action = try state.receiveHTTPPart(unwrapInboundIn(data))
            try handleAction(action, context: context)
        } catch {
            deliverOneError(error, context: context)
        }
    }
    
    private func deliverOneError(_ error: Error, context: ChannelHandlerContext) {
        established?.fail(error)
        context.fireErrorCaught(error)
    }
}

extension HTTP1ClientCONNECTTunnelHandler {
    
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
            case .deliverOneHead, .deliverOneEnd:
                break
            case .proxyEstablished:
                handleEstablished(context: context)
        }
    }
    
    private func sendClientGreeting(context: ChannelHandlerContext) throws {
        guard let ipAddress = targetAddress.ipAddress else {
            throw HTTPProxyError.invalidClientState
        }
        
        var head = HTTPRequestHead(
            version: .http1_1,
            method: .CONNECT,
            uri: "\(ipAddress):\(targetAddress.port ?? 80)"
        )
        
        if let credential = credential {
            let authorization = "Basic " + "\(credential.identity):\(credential.identityTokenString)".data(using: .utf8)!.base64EncodedString()
            head.headers.replaceOrAdd(name: "proxy-authorization", value: authorization)
        }
        
        try state.sendClientGreeting()
        
        context.write(wrapOutboundOut(.head(head)), promise: nil)
        context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
    }
    
    private func handleEstablished(context: ChannelHandlerContext) {
        established?.succeed(())
    }
}
