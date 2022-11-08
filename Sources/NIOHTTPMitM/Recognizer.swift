//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2022 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore
import NIOHTTP1
import NIOSSL

public class Recognizer: ChannelInboundHandler, RemovableChannelHandler {

    public typealias InboundIn = ByteBuffer

    private enum EventBuffer {
        case channelRead(NIOAny)
        case channelReadComplete
    }

    private enum RecognizeState {
        case waitingForData
        case waitingForComplete
        case completed
    }

    private var eventBuffer: CircularBuffer<EventBuffer>

    private var state: RecognizeState

    private let recognition: (ByteBuffer) -> Bool

    private let completion: (Bool, Channel) -> EventLoopFuture<Void>

    #if swift(>=5.7)
    @preconcurrency
    public init(
        completion: @escaping @Sendable (Bool, Channel) -> EventLoopFuture<Void>,
        recognition: @escaping @Sendable (ByteBuffer) -> Bool
    ) {
        self.eventBuffer = .init()
        self.state = .waitingForData
        self.completion = completion
        self.recognition = recognition
    }
    #else
    public init(
        completion: @escaping (Bool, Channel) -> EventLoopFuture<Void>,
        recognition: @escaping (ByteBuffer) -> Bool
    ) {
        self.eventBuffer = .init()
        self.state = .waitingForData
        self.completion = completion
        self.recognition = recognition
    }
    #endif

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch state {
            case .waitingForData:
                eventBuffer.append(.channelRead(data))
                state = .waitingForComplete
                completion(recognition(unwrapInboundIn(data)), context.channel).whenComplete {
                    switch $0 {
                        case .success:
                            while !self.eventBuffer.isEmpty {
                                let event = self.eventBuffer.removeFirst()
                                switch event {
                                    case .channelRead(let data):
                                        context.fireChannelRead(data)
                                    case .channelReadComplete:
                                        context.fireChannelReadComplete()
                                }
                            }
                            self.state = .completed
                            context.pipeline.removeHandler(context: context, promise: nil)
                        case .failure(let error):
                            context.fireErrorCaught(error)
                            context.close(promise: nil)
                    }
                }
            case .waitingForComplete:
                eventBuffer.append(.channelRead(data))

            case .completed:
                context.fireChannelRead(data)
        }
    }

    public func channelReadComplete(context: ChannelHandlerContext) {
        eventBuffer.append(.channelReadComplete)
    }
}

#if swift(>=5.7)
@available(*, unavailable)
extension Recognizer: Sendable {}
#endif

/// This handler can be used in channels that are acting as the server to recognize whether channel is communicating with SSL/TLS protocol.
final public class NIOTLSRecognizer: Recognizer {

    #if swift(>=5.7)
    /// Initialize an instance of `NIOTLSRecognizer` with specified completion handler.
    /// - Parameter completion: Then closure that will fire when recognition has completed.
    @preconcurrency
    public init(completion: @escaping @Sendable (Bool, Channel) -> EventLoopFuture<Void>) {
        super.init(completion: completion) {
            guard $0.readableBytes >= 6 else {
                return false
            }

            var byteBuffer = $0

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
    #else
    /// Initialize an instance of `NIOTLSRecognizer` with specified completion handler.
    /// - Parameter completion: Then closure that will fire when recognition has completed.
    public init(completion: @escaping (Bool, Channel) -> EventLoopFuture<Void>) {
        super.init(completion: completion) {
            guard $0.readableBytes >= 6 else {
                return false
            }

            var byteBuffer = $0

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
    #endif
}

/// This handler can be used in channels that are acting as the server to recognize whether channel is communicating with HTTP protocol.
final public class PlainHTTPRecognizer: Recognizer {

    #if swift(>=5.7)
    @preconcurrency
    /// Initialize an instance of `PlainHTTPRecognizer` with specified completion handler.
    /// - Parameter completion: Then closure that will fire when recognition has completed.
    public init(completion: @escaping @Sendable (Bool, Channel) -> EventLoopFuture<Void>) {
        super.init(completion: completion) { _ in
            return true
        }
    }
    #else
    /// Initialize an instance of `PlainHTTPRecognizer` with specified completion handler.
    /// - Parameter completion: Then closure that will fire when recognition has completed.
    public init(completion: @escaping (Bool, Channel) -> EventLoopFuture<Void>) {
        super.init(completion: completion) { _ in
            return true
        }
    }
    #endif
}
