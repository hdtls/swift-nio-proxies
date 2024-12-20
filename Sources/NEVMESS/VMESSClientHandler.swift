//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2023 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation
import NEAddressProcessing
import NIOCore

private enum VMESSWriteState {
  case headBegin
  case frameBegin
  case complete
}

final public class VMESSClientHandler: ChannelInboundHandler, ChannelOutboundHandler {

  public typealias InboundIn = VMESSPart<VMESSResponseHead, ByteBuffer>

  public typealias InboundOut = ByteBuffer

  public typealias OutboundIn = ByteBuffer

  public typealias OutboundOut = VMESSPart<VMESSRequestHead, ByteBuffer>

  private var writeState: VMESSWriteState = .headBegin
  private var version: VMESSVersion
  private var user: UUID
  private var authenticationCode: UInt8
  private var contentSecurity: ContentSecurity
  private var options: StreamOptions
  private var commandCode: CommandCode
  private var destinationAddress: Address

  public init(
    version: VMESSVersion = .v1,
    user: UUID,
    authenticationCode: UInt8 = .random(in: 0 ... .max),
    contentSecurity: ContentSecurity,
    options: StreamOptions = .chunkStream,
    commandCode: CommandCode,
    destinationAddress: Address
  ) {
    self.version = version
    self.user = user
    self.authenticationCode = authenticationCode
    self.contentSecurity = contentSecurity
    self.options = options
    self.commandCode = commandCode
    self.destinationAddress = destinationAddress
  }

  public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    switch unwrapInboundIn(data) {
    case .head(let head):
      guard head.authenticationCode == authenticationCode else {
        context.fireErrorCaught(VMESSError.authenticationFailure)
        return
      }
    case .body(let frame):
      context.fireChannelRead(wrapInboundOut(frame))
    case .end:
      break
    }
  }

  public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?)
  {
    switch writeState {
    case .headBegin:
      context.write(
        wrapOutboundOut(
          .head(
            .init(
              version: version,
              user: user,
              authenticationCode: authenticationCode,
              algorithm: contentSecurity,
              options: options,
              commandCode: commandCode,
              address: destinationAddress
            )
          )
        ),
        promise: promise
      )
      writeState = .frameBegin
      context.write(wrapOutboundOut(.body(unwrapOutboundIn(data))), promise: promise)
    case .frameBegin:
      context.write(wrapOutboundOut(.body(unwrapOutboundIn(data))), promise: promise)
    case .complete:
      context.write(wrapOutboundOut(.end), promise: promise)
      writeState = .headBegin
    }
  }
}

@available(*, unavailable)
extension VMESSClientHandler: Sendable {}
