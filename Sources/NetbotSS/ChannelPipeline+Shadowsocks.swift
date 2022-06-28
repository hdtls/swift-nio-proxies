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
import NetbotCore

extension ChannelPipeline {

    public func addSSClientHandlers(
        logger: Logger,
        algorithm: CryptoAlgorithm,
        passwordReference: String,
        taskAddress: NetAddress,
        position: Position = .last
    ) -> EventLoopFuture<Void> {
        let eventLoopFuture: EventLoopFuture<Void>

        if eventLoop.inEventLoop {
            let result = Result<Void, Error> {
                try syncOperations.addSSClientHandlers(
                    logger: logger,
                    algorithm: algorithm,
                    passwordReference: passwordReference,
                    taskAddress: taskAddress,
                    position: position
                )
            }
            eventLoopFuture = eventLoop.makeCompletedFuture(result)
        } else {
            eventLoopFuture = eventLoop.submit {
                try self.syncOperations.addSSClientHandlers(
                    logger: logger,
                    algorithm: algorithm,
                    passwordReference: passwordReference,
                    taskAddress: taskAddress,
                    position: position
                )
            }
        }

        return eventLoopFuture
    }
}

extension ChannelPipeline.SynchronousOperations {

    public func addSSClientHandlers(
        logger: Logger,
        algorithm: CryptoAlgorithm,
        passwordReference: String,
        taskAddress: NetAddress,
        position: ChannelPipeline.Position = .last
    ) throws {
        eventLoop.assertInEventLoop()
        let inboundDecoder = ResponseDecoder(
            algorithm: algorithm,
            passwordReference: passwordReference
        )
        let outboundEncoder = RequestEncoder(
            logger: logger,
            algorithm: algorithm,
            passwordReference: passwordReference,
            taskAddress: taskAddress
        )
        let handlers: [ChannelHandler] = [
            ByteToMessageHandler(inboundDecoder), MessageToByteHandler(outboundEncoder),
        ]
        try addHandlers(handlers, position: position)
    }
}
