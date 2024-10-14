//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2021 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NEAddressProcessing
import NIOCore
import NIOHTTP1

/// A channel handler that wraps a channel in HTTP CONNECT tunnel.
/// This handler can be used in channels that are acting as the client in the HTTP CONNECT tunnel proxy dialog.
final public class HTTPProxyClientHandler: ChannelDuplexHandler, RemovableChannelHandler {

  public typealias InboundIn = HTTPClientResponsePart

  public typealias OutboundIn = NIOAny

  /// The credentials used to authenticate this proxy connection.
  private let passwordReference: String

  /// A boolean value deterinse whether client should perform proxy authentication.
  private let authenticationRequired: Bool

  /// The destination for this proxy connection.
  private let destinationAddress: Address

  private enum Progress: Equatable {
    case waitingForData
    case waitingForComplete
    case completed
  }

  private var progress: Progress = .waitingForData

  private let additionalHTTPHandlers: [any RemovableChannelHandler]

  /// The HTTP proxy connection time out time amount.
  private let timeoutInterval: TimeAmount

  /// Time out shceduled task.
  private var scheduled: Scheduled<Void>?

  /// The circular buffer to buffer channel write before handshake established.
  ///
  /// All buffered write will unbuffered when proxy established.
  private var bufferedWrites: MarkedCircularBuffer<BufferedWrite>

  /// Initialize an instance of `HTTP1ClientCONNECTTunnelHandler` with specified parameters.
  ///
  /// - Parameters:
  ///   - passwordReference: Credentials for proxy authentication.
  ///   - authenticationRequired: A boolean value deterinse whether client should perform proxy authentication.
  ///   - destinationAddress: The destination for this proxy connection.
  ///   - additionalHTTPHandlers: Additional HTTP handlers use for http codec.
  ///   - timeoutInterval: A TimeAmount use to calculate deadline for handshaking timeout. The default timeout interval is 60 seconds.
  public init(
    passwordReference: String,
    authenticationRequired: Bool,
    destinationAddress: Address,
    additionalHTTPHandlers: [any RemovableChannelHandler],
    timeoutInterval: TimeAmount = .seconds(60)
  ) {
    self.passwordReference = passwordReference
    self.authenticationRequired = authenticationRequired
    self.destinationAddress = destinationAddress
    self.bufferedWrites = .init(initialCapacity: 6)
    self.additionalHTTPHandlers = additionalHTTPHandlers
    self.timeoutInterval = timeoutInterval
  }

  public func handlerAdded(context: ChannelHandlerContext) {
    if context.channel.isActive {
      performCONNECTHandshake(context: context)
    }
  }

  public func channelActive(context: ChannelHandlerContext) {
    context.fireChannelActive()
    performCONNECTHandshake(context: context)
  }

  public func channelInactive(context: ChannelHandlerContext) {
    context.fireChannelInactive()
    scheduled?.cancel()
  }

  public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    guard progress == .waitingForComplete else {
      context.fireChannelRead(data)
      return
    }

    switch (unwrapInboundIn(data), progress) {
    case (.head(let head), .waitingForComplete):
      if !(200..<300).contains(head.status.code) {
        scheduled?.cancel()
        channelClose(
          context: context,
          reason: NEHTTPError(status: head.status)
        )
      }
    case (.body, .waitingForComplete):
      break
    case (.end, .waitingForComplete):
      established(context: context)
    default:
      scheduled?.cancel()
      channelClose(context: context, reason: NEHTTPError.badRequest)
    }
  }

  public func write(
    context: ChannelHandlerContext,
    data: NIOAny,
    promise: EventLoopPromise<Void>?
  ) {
    bufferedWrites.append((data, promise))
  }

  public func flush(context: ChannelHandlerContext) {
    bufferedWrites.mark()

    // Unbuffer writes when handshake is success.
    guard progress == .completed else {
      return
    }
    unbufferWrites(context: context)
  }
}

extension HTTPProxyClientHandler {

  private typealias BufferedWrite = (data: NIOAny, promise: EventLoopPromise<Void>?)

  private func unbufferWrites(context: ChannelHandlerContext) {
    while bufferedWrites.hasMark {
      let bufferedWrite = bufferedWrites.removeFirst()
      context.write(bufferedWrite.data, promise: bufferedWrite.promise)
    }
    context.flush()

    while !bufferedWrites.isEmpty {
      let bufferedWrite = bufferedWrites.removeFirst()
      context.write(bufferedWrite.data, promise: bufferedWrite.promise)
    }
  }

  /// Sending HTTP CONNECT request to proxy server and perform a timeout schedule task.
  private func performCONNECTHandshake(context: ChannelHandlerContext) {
    guard context.channel.isActive, progress == .waitingForData else {
      return
    }

    let bs = NIOLoopBound(self, eventLoop: context.eventLoop)
    let ctx = NIOLoopBound(context, eventLoop: context.eventLoop)
    scheduled = context.eventLoop.scheduleTask(in: timeoutInterval) {
      switch bs.value.progress {
      case .waitingForData:
        preconditionFailure(
          "How can we have a scheduled timeout, if the connection is not even up?"
        )
      case .waitingForComplete:
        bs.value.channelClose(context: ctx.value, reason: NEHTTPError.requestTimeout)
      case .completed:
        break
      }
    }

    progress = .waitingForComplete

    let uri: String
    switch destinationAddress {
    case .hostPort(let host, let port):
      switch host {
      case .name(let string):
        uri = "\(string):\(port.rawValue)"
      case .ipv4(let address):
        uri = "\(address.debugDescription):\(port.rawValue)"
      case .ipv6(let address):
        uri = "\(address.debugDescription):\(port.rawValue)"
      }
    case .unix, .url:
      channelClose(context: context, reason: SocketAddressError.unsupported)
      return
    }

    var head: HTTPRequestHead = .init(version: .http1_1, method: .CONNECT, uri: uri)
    if authenticationRequired {
      head.headers.replaceOrAdd(name: "Proxy-Authorization", value: passwordReference)
    }

    context.write(NIOAny(HTTPClientRequestPart.head(head)), promise: nil)
    context.writeAndFlush(NIOAny(HTTPClientRequestPart.end(nil)), promise: nil)
  }

  private func established(context: ChannelHandlerContext) {
    let bs = NIOLoopBound(self, eventLoop: context.eventLoop)
    let ctx = NIOLoopBound(context, eventLoop: context.eventLoop)

    EventLoopFuture.andAllComplete(
      additionalHTTPHandlers.map {
        context.pipeline.removeHandler($0)
          .flatMapError { error in
            guard case .notFound = error as? ChannelPipelineError else {
              return ctx.value.eventLoop.makeFailedFuture(error)
            }
            return ctx.value.eventLoop.makeSucceededVoidFuture()
          }
      },
      on: context.eventLoop
    )
    .flatMap {
      bs.value.progress = .completed
      bs.value.unbufferWrites(context: ctx.value)
      bs.value.scheduled?.cancel()
      return ctx.value.pipeline.removeHandler(bs.value)
    }
    .whenFailure { error in
      bs.value.channelClose(context: ctx.value, reason: error)
    }
  }

  private func channelClose(context: ChannelHandlerContext, reason: any Error) {
    guard let error = reason as? NEHTTPError else {
      context.fireErrorCaught(reason)
      return
    }

    switch error.status {
    case .badRequest, .requestTimeout:
      context.close(promise: nil)
    default:
      context.fireErrorCaught(error)
    }
  }
}

@available(*, unavailable)
extension HTTPProxyClientHandler: Sendable {}
