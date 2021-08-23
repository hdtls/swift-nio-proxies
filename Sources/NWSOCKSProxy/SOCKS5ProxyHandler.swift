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

/// The result of an SLPN negotiation.
///
/// In a system expecting an SLPN negotiation to occur, a wide range of
/// possible things can happen. In the best case scenario it is possible for
/// the server and client to agree on a SOCKS5 connection to speak, in which case this
/// will be `success`. However, if for any reason it was not possible to negotiate SOCKS5
/// handshake, we should `failure` to a default choice of some kind.
///
/// Exactly what to do when failed is the responsibility of a specific
/// implementation.
public enum SLPNResult {
    case success
    case failure(Error)
}

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

    public let completion: (SLPNResult) -> EventLoopFuture<Void>

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

    var state: ConnectionState
    private var handshakeState: HandshakeState
    private var recvBuffer: ByteBuffer
    private var writeBuffer: MarkedCircularBuffer<BufferedWrite>

    init(completion: @escaping (SLPNResult) -> EventLoopFuture<Void>) {
        self.recvBuffer = ByteBufferAllocator.init().buffer(capacity: SOCKS5_MAX_RECORD_SIZE)
        self.state = .handshaking
        self.handshakeState = .hello
        self.completion = completion
        self.writeBuffer = .init(initialCapacity: 20)
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        if case .handshaking = state {
            doHandshakeStep(context: context, data: data)
        }
    }

    public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        guard state != .completion else {
            context.write(data, promise: promise)
            return
        }

        // Buffer write event that happend before handshake has beed finished.
        bufferWrite(data: data, promise: promise)
    }

    public func flush(context: ChannelHandlerContext) {
        guard state != .completion else {
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
                completion(.success).whenComplete { (_) in
                    self.unbufferWrites(context: context)
                    self.state = .completion
                    context.pipeline.removeHandler(self, promise: nil)
                }
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
