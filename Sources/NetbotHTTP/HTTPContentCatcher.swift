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
import NIOHTTP1
import NIOHTTPCompression

public final class HTTPContentCatcher<HeadT: Equatable>: ChannelInboundHandler {
    
    public typealias InboundIn = HTTPPart<HeadT, ByteBuffer>
    
    private var head: HeadT?
    private var body: ByteBuffer!
    private var trailers: HTTPHeaders?
    
    public let logger: Logger
    public let isHTTPCaptureEnabled: Bool
    public let isHTTPCompressionEnabled: Bool
    
    public init(logger: Logger = .init(label: "com.netbot.http-capture"), enableHTTPCapture: Bool, enableHTTPCompression: Bool = true) {
        self.logger = logger
        self.isHTTPCaptureEnabled = enableHTTPCapture
        self.isHTTPCompressionEnabled = enableHTTPCompression
        guard HeadT.self == HTTPRequestHead.self || HeadT.self == HTTPResponseHead.self else {
            preconditionFailure("unknown HTTP head part type \(HeadT.self)")
        }
    }
    
    public func handlerAdded(context: ChannelHandlerContext) {
        body = context.channel.allocator.buffer(capacity: 512)
        
        guard isHTTPCompressionEnabled else {
            return
        }
        
        do {
            if HeadT.self == HTTPRequestHead.self {
                try context.pipeline.syncOperations.addHandler(HTTPResponseCompressor.init(), position: .before(self))
            } else {
                try context.pipeline.syncOperations.addHandler(NIOHTTPResponseDecompressor.init(limit: .none), position: .before(self))
            }
        } catch {
            context.fireErrorCaught(error)
        }
    }
    
    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        context.fireChannelRead(data)
                
        switch unwrapInboundIn(data) {
            case .head(let head):
                self.head = head
                body.clear()
                trailers = nil
            case .body(var byteBuffer):
                if isHTTPCaptureEnabled {
                    body!.writeBuffer(&byteBuffer)
                }
            case .end(let trailers):
                var msg = "\n"
                
                if let headPart = head as? HTTPRequestHead {
                    msg += "\n\(headPart.method) \(headPart.version) \(headPart.uri)"
                    headPart.headers.forEach { field in
                        msg += "\n"
                        msg += "\(field.name) \(field.value)"
                    }
                } else {
                    let headPart = head as! HTTPResponseHead
                    msg += "\n\(headPart.version) \(headPart.status)"
                    headPart.headers.forEach { field in
                        msg += "\n"
                        msg += "\(field.name) \(field.value)"
                    }
                }
                
                if isHTTPCaptureEnabled, let str = body.readString(length: body.readableBytes) {
                    msg += "\n\(String(describing: str))"
                }
                
                trailers?.forEach { field in
                    msg += "\n"
                    msg += "\(field.name) \(field.value)"
                }
                msg += "\n"
                
                logger.info("\(msg)")
        }
    }
}
