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

import Foundation
import NIOCore
import NetbotCore

extension ChannelPipeline {

    public func addVMESSClientHandlers(
        logger: Logger = .init(label: "com.netbot.vmess"),
        username: UUID,
        destinationAddress: NetAddress,
        position: Position = .last
    ) -> EventLoopFuture<Void> {
        let eventLoopFuture: EventLoopFuture<Void>

        if eventLoop.inEventLoop {
            let result = Result<Void, Error> {
                try syncOperations.addVMESSClientHandlers(
                    logger: logger,
                    username: username,
                    destinationAddress: destinationAddress,
                    position: position
                )
            }
            eventLoopFuture = eventLoop.makeCompletedFuture(result)
        } else {
            eventLoopFuture = eventLoop.submit({
                try self.syncOperations.addVMESSClientHandlers(
                    logger: logger,
                    username: username,
                    destinationAddress: destinationAddress,
                    position: position
                )
            })
        }

        return eventLoopFuture
    }
}

extension ChannelPipeline.SynchronousOperations {

    public func addVMESSClientHandlers(
        logger: Logger = .init(label: "com.netbot.vmess"),
        username: UUID,
        destinationAddress: NetAddress,
        position: ChannelPipeline.Position = .last
    ) throws {
        eventLoop.assertInEventLoop()

        let configuration: Configuration = .init(
            id: username,
            algorithm: .aes128gcm,
            command: .tcp,
            options: .masking
        )

        let symmetricKey = SecureBytes(count: 16)

        let nonce = SecureBytes(count: 16)

        let authenticationCode = UInt8.random(in: 0...UInt8.max)

        let outboundHandler = RequestEncodingHandler(
            logger: logger,
            authenticationCode: authenticationCode,
            symmetricKey: symmetricKey,
            nonce: nonce,
            configuration: configuration,
            taskAddress: destinationAddress
        )

        let responseDecoder = ResponseHeaderDecoder(
            logger: logger,
            authenticationCode: authenticationCode,
            symmetricKey: symmetricKey,
            nonce: nonce,
            configuration: configuration
        )

        let frameDecoder = LengthFieldBasedFrameDecoder(
            logger: logger,
            symmetricKey: symmetricKey,
            nonce: nonce,
            configuration: configuration
        )

        let handlers: [ChannelHandler] = [
            ByteToMessageHandler(responseDecoder),
            ByteToMessageHandler(frameDecoder),
            outboundHandler,
        ]

        try addHandlers(handlers, position: position)
    }
}
