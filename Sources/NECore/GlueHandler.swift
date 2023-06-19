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

import NIOCore

final class GlueHandler: ChannelDuplexHandler {

  typealias InboundIn = NIOAny

  typealias OutboundIn = NIOAny

  typealias OutboundOut = NIOAny

  private var partner: GlueHandler?

  private var context: ChannelHandlerContext?

  private var pendingRead: Bool = false

  private init() {}

  func handlerAdded(context: ChannelHandlerContext) {
    self.context = context
  }

  func handlerRemoved(context: ChannelHandlerContext) {
    self.context = nil
    self.partner = nil
  }

  func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    partner?.partnerWrite(data)
  }

  func channelReadComplete(context: ChannelHandlerContext) {
    partner?.partnerFlush()
    context.fireChannelReadComplete()
  }

  func channelInactive(context: ChannelHandlerContext) {
    partner?.partnerCloseFull()
    context.fireChannelInactive()
  }

  func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
    if let event = event as? ChannelEvent, case .inputClosed = event {
      // We have read EOF.
      partner?.partnerWriteEOF()
    }
    context.fireUserInboundEventTriggered(event)
  }

  func errorCaught(context: ChannelHandlerContext, error: Error) {
    context.fireErrorCaught(error)
    partner?.partnerCloseFull()
  }

  func channelWritabilityChanged(context: ChannelHandlerContext) {
    if context.channel.isWritable {
      partner?.partnerBecameWritable()
    }
  }

  func read(context: ChannelHandlerContext) {
    if let partner, partner.partnerWritable {
      context.read()
    } else {
      pendingRead = true
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
    context?.write(data, promise: nil)
  }

  private func partnerFlush() {
    context?.flush()
  }

  private func partnerWriteEOF() {
    context?.close(mode: .output, promise: nil)
  }

  private func partnerCloseFull() {
    context?.close(promise: nil)
  }

  private func partnerBecameWritable() {
    if pendingRead {
      pendingRead = false
      context?.read()
    }
  }

  private var partnerWritable: Bool {
    return context?.channel.isWritable ?? false
  }
}
