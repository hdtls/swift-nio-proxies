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

import Foundation
import Logging
import NIOCore
import NIOHTTP1

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
    
    private var state: ConnectionState
    private var requestHead: HTTPResponseHead?
    
    public init(logger: Logger = .init(label: "com.netbot.http-client-tunnel"), credential: Credential? = nil,
                targetAddress: SocketAddress) {
        self.logger = logger
        self.credential = credential
        self.targetAddress = targetAddress
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
        guard state != .active else {
            context.fireChannelRead(data)
            return
        }
        
        do {
            switch unwrapInboundIn(data) {
                case .head(let head) where state == .active:
                    switch head.status.code {
                        case 200..<300:
                            requestHead = head
                        default:
                            throw HTTPProxyError.invalidProxyResponse(head)
                    }
                case .end where requestHead != nil:
                    try established(context: context)
                default:
                    throw HTTPProxyError.invalidHTTPOrdering
            }
        } catch {
            deliverOneError(error, context: context)
        }
    }

}

extension HTTP1ClientCONNECTTunnelHandler {
    
    private func startHandshaking(context: ChannelHandlerContext) {
        guard context.channel.isActive, state == .idle else {
            return
        }
        do {
            try state.evaluating()
            try sendClientGreeting(context: context)
        } catch {
            deliverOneError(error, context: context)
        }
    }
    
    private func sendClientGreeting(context: ChannelHandlerContext) throws {
        guard let ipAddress = targetAddress.ipAddress else {
            throw HTTPProxyError.invalidURL(url: "nil")
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
                
        context.write(wrapOutboundOut(.head(head)), promise: nil)
        context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
    }
    
    private func established(context: ChannelHandlerContext) throws {
        try state.established()
    }
    
    private func deliverOneError(_ error: Error, context: ChannelHandlerContext) {
        context.fireErrorCaught(error)
        context.close(promise: nil)
    }
}
