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

final public class TrojanClientHandler: ChannelOutboundHandler {

    public typealias OutboundIn = ByteBuffer

    private let logger: Logger
    private let password: String
    private let taskAddress: NetAddress

    private var isTunneling: Bool = false

    public init(logger: Logger, password: String, taskAddress: NetAddress) {
        self.logger = logger
        self.password = password
        self.taskAddress = taskAddress
    }

    public func write(
        context: ChannelHandlerContext,
        data: NIOAny,
        promise: EventLoopPromise<Void>?
    ) {
        guard !self.isTunneling else {
            context.write(data, promise: promise)
            return
        }

        let crlf = "\r\n"

        var data = unwrapOutboundIn(data)

        var out = context.channel.allocator.buffer(capacity: data.readableBytes)

        let hashValue = SHA224.hash(data: Array(self.password.utf8))

        out.writeString(Array(hashValue).hexString)
        out.writeString(crlf)
        out.writeInteger(0x01)
        out.writeAddress(taskAddress)
        out.writeString(crlf)
        out.writeBuffer(&data)

        context.write(NIOAny(out), promise: promise)
    }
}
