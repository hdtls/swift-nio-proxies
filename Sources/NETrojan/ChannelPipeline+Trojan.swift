//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2021 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

@_exported import NEMisc
@_exported import NIOCore

extension ChannelPipeline {

  public func addTrojanClientHandlers(
    position: ChannelPipeline.Position = .last,
    password: String,
    taskAddress: NetAddress
  ) -> EventLoopFuture<Void> {
    let eventLoopFuture: EventLoopFuture<Void>

    if eventLoop.inEventLoop {
      let result = Result<Void, Error> {
        try self.syncOperations.addTrojanClientHandlers(
          position: position,
          password: password,
          taskAddress: taskAddress
        )
      }
      eventLoopFuture = eventLoop.makeCompletedFuture(result)
    } else {
      eventLoopFuture = eventLoop.submit {
        try self.syncOperations.addTrojanClientHandlers(
          position: position,
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
    password: String,
    taskAddress: NetAddress
  ) throws {
    let handler = TrojanClientHandler(
      password: password,
      taskAddress: taskAddress
    )
    try self.addHandler(handler)
  }
}
