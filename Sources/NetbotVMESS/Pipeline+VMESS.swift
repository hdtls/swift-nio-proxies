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
import NIOPosix

extension ChannelPipeline {
    
    public func addVMESSClientHandlers(logger: Logger = .init(label: "com.netbot.vmess"),
                                       taskAddress: NetAddress,
                                       id: UUID,
                                       position: Position = .last) -> EventLoopFuture<Void> {
        let eventLoopFuture: EventLoopFuture<Void>
        
        if eventLoop.inEventLoop {
            let result = Result<Void, Error> {
                try syncOperations.addVMESSClientHandlers(logger: logger,
                                                          taskAddress: taskAddress,
                                                          id: id,
                                                          position: position)
            }
            eventLoopFuture = eventLoop.makeCompletedFuture(result)
        } else {
            eventLoopFuture = eventLoop.submit({
                try self.syncOperations.addVMESSClientHandlers(logger: logger,
                                                               taskAddress: taskAddress,
                                                               id: id,
                                                               position: position)
            })
        }
        
        return eventLoopFuture
    }
}

extension ChannelPipeline.SynchronousOperations {
    
    public func addVMESSClientHandlers(logger: Logger = .init(label: "com.netbot.vmess"),
                                       taskAddress: NetAddress,
                                       id: UUID,
                                       position: ChannelPipeline.Position = .last) throws {
        eventLoop.assertInEventLoop()
        
        let session: Session = .init(isAEAD: true)
        
        let configuration: Configuration = .init(id: id, algorithm: .aes128gcm, command: .tcp, options: .masking)
        
        let requestEncoder = RequestEncoder(logger: logger, session: session, configuration: configuration, address: taskAddress)

        let responseDecoder = ResponseDeocoder(logger: logger, session: session, configuraiton: configuration)
        
        let handlers: [ChannelHandler] = [ByteToMessageHandler(responseDecoder), MessageToByteHandler(requestEncoder)]

        try addHandlers(handlers, position: position)
    }
}
