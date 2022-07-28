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

import Logging
import NIOCore
import NIONetbotMisc

extension ChannelPipeline {

    public func addSOCKSClientHandlers(
        logger: Logger,
        username: String,
        passwordReference: String,
        authenticationRequired: Bool,
        destinationAddress: NetAddress,
        position: Position = .last
    ) -> EventLoopFuture<Void> {
        let eventLoopFuture: EventLoopFuture<Void>

        if eventLoop.inEventLoop {
            let result = Result<Void, Error> {
                try syncOperations.addSOCKSClientHandlers(
                    logger: logger,
                    username: username,
                    passwordReference: passwordReference,
                    authenticationRequired: authenticationRequired,
                    destinationAddress: destinationAddress,
                    position: position
                )
            }
            eventLoopFuture = eventLoop.makeCompletedFuture(result)
        } else {
            eventLoopFuture = eventLoop.submit({
                try self.syncOperations.addSOCKSClientHandlers(
                    logger: logger,
                    username: username,
                    passwordReference: passwordReference,
                    authenticationRequired: authenticationRequired,
                    destinationAddress: destinationAddress,
                    position: position
                )
            })
        }

        return eventLoopFuture
    }
}

extension ChannelPipeline.SynchronousOperations {

    public func addSOCKSClientHandlers(
        logger: Logger,
        username: String,
        passwordReference: String,
        authenticationRequired: Bool,
        destinationAddress: NetAddress,
        position: ChannelPipeline.Position = .last
    ) throws {
        eventLoop.assertInEventLoop()

        let handler = SOCKS5ClientHandler(
            logger: logger,
            username: username,
            passwordReference: passwordReference,
            authenticationRequired: authenticationRequired,
            destinationAddress: destinationAddress
        )

        try addHandler(handler)
    }
}
