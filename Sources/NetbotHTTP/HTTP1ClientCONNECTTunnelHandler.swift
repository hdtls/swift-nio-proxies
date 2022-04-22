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
import NetbotCore
import NIOCore
import NIOHTTP1

public final class HTTP1ClientCONNECTTunnelHandler: ChannelDuplexHandler, RemovableChannelHandler {

    public typealias InboundIn = HTTPClientResponsePart
    
    public typealias OutboundIn = NIOAny
    
    private let logger: Logger
    
    private let configuration: HTTPProxyConfigurationProtocol
    
    private let destinationAddress: NetAddress
    
    private var state: ConnectionState
    
    private var headPart: HTTPResponseHead?
    
    private var bufferedWrites: MarkedCircularBuffer<BufferedWrite>
    
    public init(logger: Logger, configuration: HTTPProxyConfigurationProtocol, destinationAddress: NetAddress) {
        self.logger = logger
        self.configuration = configuration
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
        guard state != .active else {
            context.fireChannelRead(data)
            return
        }
        
        do {
            switch unwrapInboundIn(data) {
                case .head(let head) where state == .evaluating:
                    switch head.status.code {
                        case 200..<300:
                            headPart = head
                        default:
                            throw HTTPProxyError.invalidProxyResponse(head)
                    }
                case .end where state == .evaluating && headPart != nil:
                    try established(context: context)
                default:
                    throw HTTPProxyError.invalidHTTPOrdering
            }
        } catch {
            deliverOneError(error, context: context)
        }
    }

    public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
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
        var head: HTTPRequestHead
        
        switch destinationAddress {
            case .domainPort(let domain, let port):
                head = .init(version: .http1_1, method: .CONNECT, uri: "\(domain):\(port)")
            case .socketAddress(let socketAddress):
                guard let host = socketAddress.ipAddress else {
                    throw HTTPProxyError.invalidURL(url: "nil")
                }
                head = .init(version: .http1_1, method: .CONNECT, uri: "\(host):\(socketAddress.port ?? 80)")
        }
        
        if let authorization = configuration.authorization {
            head.headers.proxyBasicAuthorization = authorization
        }
                
        context.write(NIOAny(HTTPClientRequestPart.head(head)), promise: nil)
        context.writeAndFlush(NIOAny(HTTPClientRequestPart.end(nil)), promise: nil)
    }
    
    private func established(context: ChannelHandlerContext) throws {
        context.pipeline.handler(type: HTTPRequestEncoder.self)
            .flatMap(context.pipeline.removeHandler(_:))
            .flatMap { context.pipeline.handler(type: ByteToMessageHandler<HTTPResponseDecoder>.self) }
            .flatMap(context.pipeline.removeHandler(_:))
            .flatMapThrowing { _ in
                self.unbufferWrites(context: context)
                try self.state.established()
            }
            .flatMap { context.pipeline.removeHandler(self) }
            .whenFailure { error in
                self.deliverOneError(error, context: context)
            }
    }
    
    private func deliverOneError(_ error: Error, context: ChannelHandlerContext) {
        context.fireErrorCaught(error)
        context.close(promise: nil)
    }
}
