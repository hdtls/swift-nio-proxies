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

import Logging
import NIOCore
import NIOHTTP1

public final class HTTPCaptureHandler<HeadT: Equatable>: ChannelInboundHandler {

    public typealias InboundIn = HTTPPart<HeadT, ByteBuffer>

    private var head: HeadT?
    private var body: ByteBuffer!
    private var trailers: HTTPHeaders?

    public let logger: Logger

    public init(logger: Logger) {
        self.logger = logger

        guard HeadT.self == HTTPRequestHead.self || HeadT.self == HTTPResponseHead.self else {
            preconditionFailure("unknown HTTP head part type \(HeadT.self)")
        }
    }

    public func handlerAdded(context: ChannelHandlerContext) {
        body = context.channel.allocator.buffer(capacity: 512)
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        context.fireChannelRead(data)

        switch unwrapInboundIn(data) {
            case .head(let head):
                self.head = head
                body.clear()
                trailers = nil
            case .body(var byteBuffer):
                body.writeBuffer(&byteBuffer)
            case .end(let trailers):
                var msg = "\n"

                if let headPart = head as? HTTPRequestHead {
                    msg += headPart.prettyPrintDescription
                } else {
                    let headPart = head as! HTTPResponseHead
                    msg += headPart.headers.prettyPrintDescription
                }

                if let str = body.readString(length: body.readableBytes) {
                    msg += "\n\(String(describing: str))"
                }

                msg += "\n" + (trailers?.prettyPrintDescription ?? "")

                logger.info("\(msg)")
        }
    }
}

extension HTTPHeaders {

    var prettyPrintDescription: String {
        self.map { field in
            "\(field.name) \(field.value)"
        }.joined(separator: "\n")
    }
}

extension HTTPRequestHead {

    var prettyPrintDescription: String {
        "\(self.method) \(self.version) \(self.uri)\n\( self.headers.prettyPrintDescription)"
    }
}

extension HTTPResponseHead {

    var prettyPrintDescription: String {
        "\(self.version) \(self.status)\n\(self.headers.prettyPrintDescription)"
    }
}
