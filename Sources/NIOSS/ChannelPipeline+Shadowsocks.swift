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

import NIOCore
import NIONetbotMisc

extension ChannelPipeline {

    public func addSSClientHandlers(
        position: Position = .last,
        algorithm: Algorithm,
        passwordReference: String,
        taskAddress: NetAddress
    ) -> EventLoopFuture<Void> {
        let eventLoopFuture: EventLoopFuture<Void>

        if eventLoop.inEventLoop {
            let result = Result<Void, Error> {
                try syncOperations.addSSClientHandlers(
                    position: position,
                    algorithm: algorithm,
                    passwordReference: passwordReference,
                    taskAddress: taskAddress
                )
            }
            eventLoopFuture = eventLoop.makeCompletedFuture(result)
        } else {
            eventLoopFuture = eventLoop.submit {
                try self.syncOperations.addSSClientHandlers(
                    position: position,
                    algorithm: algorithm,
                    passwordReference: passwordReference,
                    taskAddress: taskAddress
                )
            }
        }

        return eventLoopFuture
    }
}

extension ChannelPipeline.SynchronousOperations {

    public func addSSClientHandlers(
        position: ChannelPipeline.Position = .last,
        algorithm: Algorithm,
        passwordReference: String,
        taskAddress: NetAddress
    ) throws {
        eventLoop.assertInEventLoop()
        let inboundDecoder = ResponseDecoder(
            algorithm: algorithm,
            passwordReference: passwordReference
        )
        let outboundEncoder = RequestEncoder(
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
