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

extension ChannelPipeline {

    public func addTrojanClientHandlers(
        position: ChannelPipeline.Position = .last,
        logger: Logger,
        password: String,
        taskAddress: NetAddress
    ) -> EventLoopFuture<Void> {
        let eventLoopFuture: EventLoopFuture<Void>

        if eventLoop.inEventLoop {
            let result = Result<Void, Error> {
                try self.syncOperations.addTrojanClientHandlers(
                    position: position,
                    logger: logger,
                    password: password,
                    taskAddress: taskAddress
                )
            }
            eventLoopFuture = eventLoop.makeCompletedFuture(result)
        } else {
            eventLoopFuture = eventLoop.submit {
                try self.syncOperations.addTrojanClientHandlers(
                    position: position,
                    logger: logger,
                    password: password,
                    taskAddress: taskAddress
                )
            }
        }

        return eventLoopFuture
    }
}

extension ChannelPipeline.SynchronousOperations {

    public func addTrojanClientHandlers(
        position: ChannelPipeline.Position = .last,
        logger: Logger,
        password: String,
        taskAddress: NetAddress
    ) throws {
        let sslContext = try NIOSSLContext(configuration: .makeClientConfiguration())
        let sslHandler = try NIOSSLClientHandler(context: sslContext, serverHostname: nil)
        let clientHandler = TrojanClientHandler(
            logger: logger,
            password: password,
            taskAddress: taskAddress
        )
        let handlers: [ChannelHandler] = [sslHandler, clientHandler]

        try self.addHandlers(handlers)
    }
}