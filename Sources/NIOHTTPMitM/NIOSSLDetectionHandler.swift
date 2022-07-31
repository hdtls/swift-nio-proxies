//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2022 Junfeng Zhang. and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore
import NIOSSL

/// This handler can be used in channels that are acting as the server to detect whether channel is perform SSL handshaking.
final public class NIOSSLDetectionHandler: ChannelInboundHandler, RemovableChannelHandler {

    public typealias InboundIn = ByteBuffer

    /// The `CircularBuffer<NIOAny>` used to store channel read buffer.
    private var eventBuffer: CircularBuffer<NIOAny> = .init(initialCapacity: 6)

    private let completion: (Bool, Channel) -> EventLoopFuture<Void>

    private enum DetectionState {
        case idle
        case waitingForData(ByteBuffer)
        case waitingForComplete
        case completed
    }

    private var state = DetectionState.idle

    /// Initialize an instance of `NIOSSLDetectionHandler` with specified tls configuration.
    /// - Parameter context: The context object for `NIOSSLServerHandler`.
    public init(completion: @escaping (Bool, Channel) -> EventLoopFuture<Void>) {
        self.completion = completion
    }

    public func handlerAdded(context: ChannelHandlerContext) {
        state = .waitingForData(context.channel.allocator.buffer(capacity: 6))
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch state {
            case .idle:
                preconditionFailure("ChannelRead called before added.")
            case .waitingForData(var byteBuffer):
                eventBuffer.append(data)
                byteBuffer.writeImmutableBuffer(unwrapInboundIn(data))

                guard byteBuffer.readableBytes >= 6 else {
                    state = .waitingForData(byteBuffer)
                    return
                }
                state = .waitingForComplete
                completion(containsSSLHandshake(in: byteBuffer), context.channel).whenComplete {
                    _ in
                    self.state = .completed
                    while !self.eventBuffer.isEmpty {
                        let data = self.eventBuffer.removeFirst()
                        context.pipeline.fireChannelRead(data)
                    }
                    context.pipeline.removeHandler(context: context, promise: nil)
                }

            case .waitingForComplete:
                eventBuffer.append(data)

            case .completed:
                context.fireChannelRead(data)
        }
    }

    private func containsSSLHandshake(in buffer: ByteBuffer) -> Bool {
        var byteBuffer = buffer

        // Byte   0  = SSL record type = 22 (SSL3_RT_HANDSHAKE)
        // Bytes 1-2 = SSL version (major/minor)
        // Bytes 3-4 = Length of data in the record (excluding the header itself).
        // Byte   5  = Handshake type
        // Bytes 6-8 = Length of data to follow in this record
        // Bytes 9-n = Command-specific data

        let contentType = byteBuffer.readInteger(as: UInt8.self)

        // SSL3_RT_HANDSHAKE 22(x'16')
        guard contentType == 0x16 else {
            return false
        }

        // Skip bytes that represent as version and record data length.
        byteBuffer.moveReaderIndex(forwardBy: 4)

        let handshakeType = byteBuffer.readInteger(as: UInt8.self)!

        // SSL3_MT_HELLO_REQUEST (x'00')
        // SSL3_MT_CLIENT_HELLO (x'01')
        // SSL3_MT_SERVER_HELLO (x'02')
        // SSL3_MT_NEWSESSION_TICKET (x'04')
        // SSL3_MT_CERTIFICATE (x'0B')
        // SSL3_MT_SERVER_KEY_EXCHANGE (x'0C')
        // SSL3_MT_CERTIFICATE_REQUEST (x'0D')
        // SSL3_MT_SERVER_DONE (x'0E')
        // SSL3_MT_CERTIFICATE_VERIFY (x'0F')
        // SSL3_MT_CLIENT_KEY_EXCHANGE (x'10')
        // SSL3_MT_FINISHED (x'14')
        let handshakeTypes: [UInt8] = [
            0x00, 0x01, 0x02, 0x04, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x14,
        ]

        return handshakeTypes.contains(handshakeType)
    }
}
