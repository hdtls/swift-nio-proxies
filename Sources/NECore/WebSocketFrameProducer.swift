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
import NIOWebSocket

/// A handler that unmask inbound `WebSocketFrame` to `ByteBuffer` and response to control codes, it also mask all outbound
/// `IOData` to `WebSocketFrame` with `.binary` opcode.
final public class WebSocketFrameProducer: ChannelInboundHandler, ChannelOutboundHandler {

  public typealias InboundIn = WebSocketFrame

  public typealias InboundOut = ByteBuffer

  public typealias OutboundIn = IOData

  public typealias OutboundOut = WebSocketFrame

  private var waitingForClose = false

  public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    let frame = unwrapInboundIn(data)
    switch frame.opcode {
    case .continuation:
      break
    case .text, .binary:
      context.fireChannelRead(wrapInboundOut(frame.unmaskedData))
    case .connectionClose:
      guard !waitingForClose else {
        context.close(promise: nil)
        return
      }
      let promise = context.eventLoop.makePromise(of: Void.self)
      var unmaskedData = frame.unmaskedData
      let code = unmaskedData.readWebSocketErrorCode() ?? .unknown(1005)
      close(context: context, code: code, promise: promise)
      promise.futureResult.whenComplete { _ in
        context.close(promise: nil)
      }
    case .ping:
      guard frame.fin else {
        close(context: context, code: .protocolError, promise: nil)
        return
      }
      let response = WebSocketFrame(
        fin: true,
        opcode: .pong,
        maskKey: .random(),
        data: frame.unmaskedData
      )
      context.writeAndFlush(wrapOutboundOut(response), promise: nil)
    case .pong:
      guard frame.fin else {
        close(context: context, code: .protocolError, promise: nil)
        return
      }
    default:
      break
    }
  }

  private func close(
    context: ChannelHandlerContext,
    code: WebSocketErrorCode = .goingAway,
    promise: EventLoopPromise<Void>?
  ) {
    guard context.channel.isActive else {
      promise?.succeed(())
      return
    }
    guard !waitingForClose else {
      promise?.succeed(())
      return
    }
    waitingForClose = true

    let codeAsInt = UInt16(webSocketErrorCode: code)

    /// Code 1005 and 1006 are used to report errors to the application, but must never be sent over
    /// the wire (per https://tools.ietf.org/html/rfc6455#section-7.4)
    let errorCode: WebSocketErrorCode =
      codeAsInt == 1005 || codeAsInt == 1006 ? .normalClosure : code

    var buffer = context.channel.allocator.buffer(capacity: MemoryLayout<UInt16>.size)
    buffer.write(webSocketErrorCode: errorCode)
    let frame = WebSocketFrame(
      fin: true,
      opcode: .connectionClose,
      maskKey: .random(),
      data: buffer
    )
    context.writeAndFlush(wrapOutboundOut(frame), promise: promise)
  }

  public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?)
  {
    switch unwrapOutboundIn(data) {
    case .byteBuffer(let buffer):
      context.write(
        wrapOutboundOut(
          WebSocketFrame(fin: true, opcode: .binary, maskKey: .random(), data: buffer)
        ),
        promise: promise
      )
    case .fileRegion:
      promise?.fail(ChannelError.operationUnsupported)
    }
  }
}

/// Make `WebSocketFrameEncoder` removable so we can remove and reorder pipeline handlers.
extension WebSocketFrameEncoder: RemovableChannelHandler {}
