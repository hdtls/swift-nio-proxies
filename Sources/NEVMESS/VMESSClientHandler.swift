//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2023 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore

final public class VMESSClientHandler: ChannelInboundHandler {

  public typealias InboundIn = VMESSPart<VMESSResponseHead, ByteBuffer>

  public typealias InboundOut = ByteBuffer

  public init() {}

  public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    switch unwrapInboundIn(data) {
    case .head:
      break
    case .body(let frame):
      context.fireChannelRead(wrapInboundOut(frame))
    case .end:
      break
    }
  }
}

@available(*, unavailable)
extension VMESSClientHandler: Sendable {}
