
    ///===----------------------------------------------------------------------===//
    //
    // This source file is part of the SwiftNIO open source project
    //
    // Copyright (c) 2019 Apple Inc. and the SwiftNIO project authors
    // Licensed under Apache License v2.0
    //
    // See LICENSE.txt for license information
    // See CONTRIBUTORS.txt for the list of SwiftNIO project authors
    //
    // SPDX-License-Identifier: Apache-2.0
    //
    //===----------------------------------------------------------------------===//

import NIO
@_exported import Logging

public final class GlueHandler: ChannelDuplexHandler {
    public typealias InboundIn = NIOAny
    public typealias OutboundIn = NIOAny
    public typealias OutboundOut = NIOAny
    
    private var partner: GlueHandler?
    
    private var context: ChannelHandlerContext?
    
    private var pendingRead: Bool = false
    
    public let logger: Logger = .init(label: "me.akii.glue-logging")
    
    private init() { }
    
    public func handlerAdded(context: ChannelHandlerContext) {
        self.context = context
    }
    
    public func handlerRemoved(context: ChannelHandlerContext) {
        self.context = nil
        self.partner = nil
    }
    
    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        self.partner?.partnerWrite(data)
    }
    
    public func channelReadComplete(context: ChannelHandlerContext) {
        self.partner?.partnerFlush()
    }
    
    public func channelInactive(context: ChannelHandlerContext) {
        self.partner?.partnerCloseFull()
    }
    
    public func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if let event = event as? ChannelEvent, case .inputClosed = event {
                // We have read EOF.
            self.partner?.partnerWriteEOF()
        }
    }
    
    public func errorCaught(context: ChannelHandlerContext, error: Error) {
        self.partner?.partnerCloseFull()
    }
    
    public func channelWritabilityChanged(context: ChannelHandlerContext) {
        if context.channel.isWritable {
            self.partner?.partnerBecameWritable()
        }
    }
    
    public func read(context: ChannelHandlerContext) {
        if let partner = self.partner, partner.partnerWritable {
            context.read()
        } else {
            self.pendingRead = true
        }
    }
}


extension GlueHandler {
    
    public static func matchedPair() -> (GlueHandler, GlueHandler) {
        let first = GlueHandler()
        
        let second = GlueHandler()
        
        first.partner = second
        second.partner = first
        
        return (first, second)
    }
}


extension GlueHandler {
    
    private func partnerWrite(_ data: NIOAny) {
        self.context?.write(data, promise: nil)
    }
    
    private func partnerFlush() {
        self.context?.flush()
    }
    
    private func partnerWriteEOF() {
        self.context?.close(mode: .output, promise: nil)
    }
    
    private func partnerCloseFull() {
        self.context?.close(promise: nil)
    }
    
    private func partnerBecameWritable() {
        if self.pendingRead {
            self.pendingRead = false
            self.context?.read()
        }
    }
    
    private var partnerWritable: Bool {
        return self.context?.channel.isWritable ?? false
    }
}
