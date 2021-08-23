//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright © 2019 Netbot Ltd. and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIO
import NIOHTTP1

public final class HTTPClientProxyHandler: ChannelDuplexHandler, RemovableChannelHandler {

    public typealias InboundIn = HTTPClientResponsePart
    public typealias OutboundIn = HTTPClientRequestPart
    public typealias OutboundOut = HTTPClientRequestPart

    enum ConnectionState {
        case handshaking
        case completion
    }

    private var state: ConnectionState
    private var writeBuffer: MarkedCircularBuffer<BufferedWrite>

    public var configuration: ProxyConfiguration
    public let completion: (Channel) -> EventLoopFuture<Void>
    
    public init(configuration: ProxyConfiguration, completion: @escaping (Channel) -> EventLoopFuture<Void>) {
        self.configuration = configuration
        self.state = .handshaking
        self.writeBuffer = .init(initialCapacity: 20)
        self.completion = completion
    }

    public func channelActive(context: ChannelHandlerContext) {
        writeHEAD(context: context)
        context.fireChannelActive()
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {

        switch state {
        case .handshaking:
            doHandshakeStep(context: context, data: data)
        case .completion:
            context.fireChannelRead(data)
        }
    }

    public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {

        // Buffer write event that happend before handshake has beed finished.
        bufferWrite(data: data, promise: promise)
    }

    public func flush(context: ChannelHandlerContext) {
        bufferFlush()
    }

    private func writeHEAD(context: ChannelHandlerContext) {
        guard let taskAddress = configuration.taskAddress else {
            return
        }

        var hostname: String = ""

        switch taskAddress {
        case .v4(let addr):
            hostname = addr.host
        case .v6(let addr):
            hostname = addr.host
        default:
            assertionFailure("This should never happen.")
        }
        
        var head = HTTPRequestHead.init(
            version: .init(major: 1, minor: 1),
            method: .CONNECT,
            uri: "\(hostname):\(taskAddress.port ?? 80)"
        )
        
        head.headers.add(name: "proxy-connection", value: "keep-alive")
//        if let authorization = configuration.basicAuthorization {
//            head.headers.add(name: "proxy-authorization", value: authorization.headerValue)
//        }
        
        context.write(wrapOutboundOut(.head(head)), promise: nil)
        context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
    }

    private func doHandshakeStep(context: ChannelHandlerContext, data: NIOAny) {
        let res = unwrapInboundIn(data)
        switch res {
        case .head(let head):
            switch head.status.code {
            case 200..<300:
                break
            default:
                context.fireErrorCaught(HTTPProxyError.invalidProxyResponse)
            }
        case .body:
            break
        case .end:
            completion(context.channel).whenComplete { (_) in
                self.unbufferWrites(context: context)
                self.state = .completion
                context.pipeline.removeHandler(self, promise: nil)
            }
        }
    }
}

// MARK: - Code that handles buffering/unbuffering writes.
extension HTTPClientProxyHandler {

    private typealias BufferedWrite = (data: NIOAny, promise: EventLoopPromise<Void>?)

    private func bufferWrite(data: NIOAny, promise: EventLoopPromise<Void>?) {
        writeBuffer.append((data, promise))
    }

    private func bufferFlush() {
        writeBuffer.mark()
    }

    private func unbufferWrites(context: ChannelHandlerContext) {

        if writeBuffer.hasMark {
            while !writeBuffer.isEmpty && writeBuffer.hasMark {
                let write = writeBuffer.removeFirst()
                context.write(write.data, promise: write.promise)
            }
            context.flush()
        }

        while !writeBuffer.isEmpty {
            let write = writeBuffer.removeFirst()
            context.write(write.data, promise: write.promise)
        }
    }
}
