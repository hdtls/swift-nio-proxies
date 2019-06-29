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

enum HTTPProxyError: Error {
    case invalidProxyResponse
}

public final class HTTPProxyHandler: ChannelDuplexHandler, RemovableChannelHandler {

    public typealias InboundIn = HTTPClientResponsePart
    public typealias OutboundIn = HTTPClientRequestPart
    public typealias OutboundOut = HTTPClientRequestPart

    enum State {
        case setup
        case preparing
        case ready
    }

    enum Event {
        case write(NIOAny, EventLoopPromise<Void>?)
        case flush
    }

    var hostname: String = ""
    var port: Int = 0

    private var readState: State = .setup

    private var writeBuffer: CircularBuffer<Event> = .init()
    private var readBuffer: CircularBuffer<NIOAny> = .init()

    public let completion: (Channel) -> EventLoopFuture<Void>

    public init(completion: @escaping (Channel) -> EventLoopFuture<Void>) {
        self.completion = completion
    }

    public func channelActive(context: ChannelHandlerContext) {
        sendHTTPConnectRequest(contex: context)
        context.fireChannelActive()
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {

        switch readState {
        case .setup:
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
                readState = .preparing
                _ = channelDidConnected(context: context)
            }
        case .preparing:
            readBuffer.append(data)
        case .ready:
            context.fireChannelRead(data)
        }
    }

    public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        writeBuffer.append(.write(data, promise))
        context.fireChannelWritabilityChanged()
    }

    public func flush(context: ChannelHandlerContext) {
        writeBuffer.append(.flush)
    }

    private func sendHTTPConnectRequest(contex: ChannelHandlerContext) {
        let headers = HTTPHeaders([("proxy-connection", "keep-alive")])
        let head = HTTPRequestHead.init(
            version: .init(major: 1, minor: 1),
            method: .CONNECT,
            uri: "\(hostname):\(port)",
            headers: headers
        )

        contex.write(wrapOutboundOut(.head(head)), promise: nil)
        contex.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
    }

    private func channelDidConnected(context: ChannelHandlerContext) -> EventLoopFuture<Void> {
        return completion(context.channel).flatMap {

            // forward any buffered reads
            while !self.readBuffer.isEmpty {
                let readBuffer = self.readBuffer.removeFirst()
                context.fireChannelRead(readBuffer)
            }

            while !self.writeBuffer.isEmpty {
                switch self.writeBuffer.removeFirst() {
                case .write(let data, let promise):
                    context.write(data, promise: promise)
                case .flush:
                    context.flush()
                }
            }

            self.readState = .ready

            return context.pipeline.removeHandler(self)
        }
    }
}
