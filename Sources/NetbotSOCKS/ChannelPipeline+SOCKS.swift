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
import NetbotCore
import NIOCore

extension ChannelPipeline {
    
    public func addSOCKSClientHandlers(logger: Logger = .init(label: "com.netbot.socks"),
                                    taskAddress: NetAddress,
                                    credential: Credential?,
                                    position: Position = .last) -> EventLoopFuture<Void> {
        let eventLoopFuture: EventLoopFuture<Void>
        
        if eventLoop.inEventLoop {
            let result = Result<Void, Error> {
                try syncOperations.addSOCKSClientHandlers(logger: logger,
                                                       taskAddress: taskAddress,
                                                          credential: credential,
                                                       position: position)
            }
            eventLoopFuture = eventLoop.makeCompletedFuture(result)
        } else {
            eventLoopFuture = eventLoop.submit({
                try self.syncOperations.addSOCKSClientHandlers(logger: logger,
                                                            taskAddress: taskAddress,
                                                               credential: credential,
                                                            position: position)
            })
        }
        
        return eventLoopFuture
    }
}

extension ChannelPipeline.SynchronousOperations {
    
    public func addSOCKSClientHandlers(logger: Logger = .init(label: "com.netbot.socks"),
                                    taskAddress: NetAddress,
                                    credential: Credential?,
                                    position: ChannelPipeline.Position = .last) throws {
        eventLoop.assertInEventLoop()
        try addHandler(SOCKS5ClientHandler(credential: credential, targetAddress: taskAddress))
    }
}
