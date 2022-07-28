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

    public func addSOCKSClientHandlers(
        position: Position = .last,
        username: String,
        passwordReference: String,
        authenticationRequired: Bool,
        destinationAddress: NetAddress
    ) -> EventLoopFuture<Void> {
        let eventLoopFuture: EventLoopFuture<Void>

        if eventLoop.inEventLoop {
            let result = Result<Void, Error> {
                try syncOperations.addSOCKSClientHandlers(
                    position: position,
                    username: username,
                    passwordReference: passwordReference,
                    authenticationRequired: authenticationRequired,
                    destinationAddress: destinationAddress
                )
            }
            eventLoopFuture = eventLoop.makeCompletedFuture(result)
        } else {
            eventLoopFuture = eventLoop.submit({
                try self.syncOperations.addSOCKSClientHandlers(
                    position: position,
                    username: username,
                    passwordReference: passwordReference,
                    authenticationRequired: authenticationRequired,
                    destinationAddress: destinationAddress
                )
            })
        }

        return eventLoopFuture
    }
}

extension ChannelPipeline.SynchronousOperations {

    public func addSOCKSClientHandlers(
        position: ChannelPipeline.Position = .last,
        username: String,
        passwordReference: String,
        authenticationRequired: Bool,
        destinationAddress: NetAddress
    ) throws {
        eventLoop.assertInEventLoop()

        let handler = SOCKS5ClientHandler(
            username: username,
            passwordReference: passwordReference,
            authenticationRequired: authenticationRequired,
            destinationAddress: destinationAddress
        )

        try addHandler(handler)
    }
}
