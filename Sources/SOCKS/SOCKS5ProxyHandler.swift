//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright © 2019 Netbot Ltd. All rights reserved. and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIO
import Logging

private let SOCKS5_MAX_RECORD_SIZE = 16 * 1024
/// The base class for all SOCKS5 proxy handlers. This class cannot actually be instantiated by
/// users directly: instead, users must select which mode they would like their handler to
/// operate in, client or server.
///
/// This class exists to deal with the reality that for almost the entirety of the lifetime
/// of a SOCKS5 proxy connection.
/// For this reason almost the entirety of the implementation for the channel and server
/// handlers in SOCKS5 proxy is shared, in the form of this parent class.
public class SOCKS5ProxyHandler: ChannelDuplexHandler, RemovableChannelHandler, RFC1918 {
    public typealias InboundIn = ByteBuffer
    public typealias OutboundOut = ByteBuffer
    public typealias OutboundIn = ByteBuffer

    var method: Method = .noAuth

    enum ConnectionState {
        case handshaking
        case prepareLinking
        case completion
    }

    private enum HandshakeState {
        case hello
        case authentication
        case reply
    }
    
    let logger = Logger.init(label: "me.akii.socks5-logging")

    var connectionState: ConnectionState
    private var handshakeState: HandshakeState
    private var recvBuffer: ByteBuffer
    private var writeBuffer: MarkedCircularBuffer<BufferedWrite>

    init() {
        self.recvBuffer = ByteBufferAllocator.init().buffer(capacity: SOCKS5_MAX_RECORD_SIZE)
        self.connectionState = .handshaking
        self.handshakeState = .hello
        self.writeBuffer = .init(initialCapacity: 20)
    }

    public func handlerAdded(context: ChannelHandlerContext) {
        
    }
    
    public func channelActive(context: ChannelHandlerContext) {
        
    }
    
    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        if case .handshaking = connectionState {
            doHandshakeStep(context: context, data: data)
        }
    }

    public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        guard connectionState != .completion else {
            context.write(data, promise: promise)
            return
        }

        // Buffer write event that happend before handshake has beed finished.
        bufferWrite(data: data, promise: promise)
    }

    public func flush(context: ChannelHandlerContext) {
        guard connectionState != .completion else {
            context.flush()
            return
        }

        bufferFlush()
    }

    private func doHandshakeStep(context: ChannelHandlerContext, data: NIOAny) {

        var byteBuffer = unwrapInboundIn(data)
        recvBuffer.writeBuffer(&byteBuffer)

        do {
            switch handshakeState {
            case .hello:
                try recvHMsg(context: context, byteBuffer: &recvBuffer)
                handshakeState = method == .noAuth ? .reply : .authentication
            case .authentication:
                try recvAMsg(context: context, byteBuffer: &recvBuffer)
                handshakeState = .reply
            case .reply:
                try recvRELMsg(context: context, byteBuffer: &recvBuffer)

                // Notify that handshake finished.
                unbufferWrites(context: context)
                connectionState = .completion
                context.pipeline.removeHandler(self, promise: nil)
            }

            // Discard readed byte to make readIndex begin with zero.
            recvBuffer.discardReadBytes()
        } catch {
            if let err = error as? SOCKS5ProxyError {
                if err == SOCKS5ProxyError.serializeFailed(reason: .needMoreBytes) {

                    // Because we have read some data in the execution of this method,
                    // when the data is insufficient, we need to re-index to ensure the
                    // data integrity of the next execution of the method.
                    recvBuffer.moveReaderIndex(to: 0)
                    return
                }
            }
            context.fireErrorCaught(error)
        }
    }

    // MARK: - Code that handles RFC1918 SOCKS5 handshake
    public func recvHMsg(context: ChannelHandlerContext, byteBuffer: inout ByteBuffer) throws {
        fatalError("this must be overridden by sub class")
    }

    public func writeHMsg(context: ChannelHandlerContext) {
        fatalError("this must be overridden by sub class")
    }

    public func recvAMsg(context: ChannelHandlerContext, byteBuffer: inout ByteBuffer) throws {
        fatalError("this must be overridden by sub class")
    }

    public func writeAMsg(context: ChannelHandlerContext) {
        fatalError("this must be overridden by sub class")
    }

    public func recvRELMsg(context: ChannelHandlerContext, byteBuffer: inout ByteBuffer) throws {
        fatalError("this must be overridden by sub class")
    }

    public func writeRELMsg(context: ChannelHandlerContext) {
        fatalError("this must be overridden by sub class")
    }
}

// MARK: - Code that handles buffering/unbuffering writes.
extension SOCKS5ProxyHandler {
    private typealias BufferedWrite = (data: NIOAny, promise: EventLoopPromise<Void>?)

    private func bufferWrite(data: NIOAny, promise: EventLoopPromise<Void>?) {
        writeBuffer.append((data, promise))
    }

    private func bufferFlush() {
        writeBuffer.mark()
    }

    private func unbufferWrites(context: ChannelHandlerContext) {
        while writeBuffer.hasMark && !writeBuffer.isEmpty {
            let write = writeBuffer.removeFirst()
            context.write(write.data, promise: write.promise)
        }
        context.flush()
        
        while !writeBuffer.isEmpty {
            let write = writeBuffer.removeFirst()
            context.write(write.data, promise: write.promise)
        }
    }
}
