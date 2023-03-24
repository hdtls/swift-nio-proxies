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

@_exported import NIOCore

public final class GlueHandler: ChannelDuplexHandler {

  public typealias InboundIn = NIOAny
  public typealias OutboundIn = NIOAny
  public typealias OutboundOut = NIOAny

  private var partner: GlueHandler?

  private var context: ChannelHandlerContext?

  private var pendingRead: Bool = false

  private init() {}

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
    context.fireErrorCaught(error)
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
    guard let context = context else {
      return
    }
    context.write(data, promise: nil)
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
