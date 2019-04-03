//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright © 2019 Netbot Ltd. and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIO
import NIOHTTP1

extension ChannelPipeline {
    
    public func configureHTTPProxyPipeline(position: ChannelPipeline.Position = .last,
                                           withPipeliningAssistance pipelining: Bool = false,
                                           httpProxyUpgrader: HTTPProxyUpgrader,
                                           completion: @escaping (ChannelHandlerContext) -> Void) -> EventLoopFuture<Void> {
        let httpEncoder = HTTPResponseEncoder()
        let httpDecoder = HTTPRequestDecoder(leftOverBytesStrategy: .forwardBytes)
        
        var handlers: [RemovableChannelHandler] = [httpEncoder, ByteToMessageHandler(httpDecoder)]
        
        if pipelining {
            handlers.append(HTTPServerPipelineHandler())
        }
        
        let extraHTTPHandlers = Array(handlers.dropFirst())
        let upgraderHandler = HTTPProxyUpgradeHandler(httpEncoder: httpEncoder,
                                                      extraHTTPHandlers: extraHTTPHandlers,
                                                      upgrader: httpProxyUpgrader,
                                                      completion: completion)
        handlers.append(upgraderHandler)

        return addHandlers(handlers, position: position)
    }
}
