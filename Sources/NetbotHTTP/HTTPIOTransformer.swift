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

import NIO
import NIOHTTP1

/// Transfer inbound from `HTTPPart<HeadT, ByteBuffer>` to `HTTPPart<HeadT, IOData>`.
public final class HTTPIOTransformer<HeadT: Equatable>: ChannelInboundHandler {
    
    public typealias InboundIn = HTTPPart<HeadT, ByteBuffer>
    public typealias InboundOut = HTTPPart<HeadT, IOData>
        
    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
            case .head(let head):
                context.fireChannelRead(wrapInboundOut(.head(head)))
            case .body(let byteBuffer):
                context.fireChannelRead(wrapInboundOut(.body(.byteBuffer(byteBuffer))))
            case .end(let trailers):
                context.fireChannelRead(wrapInboundOut(.end(trailers)))
        }
    }
}
