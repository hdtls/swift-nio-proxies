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

/// Add this handshake handler to the front of your channel, closest to the network.
/// The handler will receive bytes from the network and parse to enforce SOCKSv5 protocol correctness.
final public class SOCKS5ServerHandler<Connection>: ChannelInboundHandler {

  public typealias InboundIn = ByteBuffer

  public typealias InboundOut = ByteBuffer

  public typealias OutboundOut = ByteBuffer

  public typealias NegotiationResult = (any Channel, Connection)

  private enum Progress: Equatable {
    case waitingForGreeting(ByteBuffer?)
    case waitingForAuthorizing(ByteBuffer)
    case waitingForRequest(ByteBuffer)
    case completed
  }

  private var progress: Progress = .waitingForGreeting(nil)

  private enum EventBuffer {
    case channelRead(data: NIOAny)
    case channelReadComplete
  }

  /// Buffered channel read buffer.
  private var eventBuffer: CircularBuffer<EventBuffer> = .init(initialCapacity: 2)

  /// The usename used to authenticate this proxy connection.
  private let username: String

  /// The password used to authenticate this proxy connection.
  private let passwordReference: String

  /// A boolean value deterinse whether server should evaluate proxy authentication request.
  private let authenticationRequired: Bool

  private var negotiationResultPromise: EventLoopPromise<NegotiationResult>?

  public var negotiationResultFuture: EventLoopFuture<NegotiationResult> {
    guard let negotiationResultPromise else {
      preconditionFailure(
        "Tried to access the negotiation result before the handler was added to the pipeline"
      )
    }
    return negotiationResultPromise.futureResult
  }

  private let channelInitializer: @Sendable (Address) -> EventLoopFuture<NegotiationResult>

  /// Initialize an instance of `SOCKS5ServerHandler` with specified parameters.
  ///
  /// - Parameters:
  ///   - username: Username for proxy authentication.
  ///   - passwordReference: Password for proxy authentication.
  ///   - authenticationRequired: A boolean value deterinse whether server should evaluate proxy authentication request.
  ///   - channelInitializer: The outbound channel initialzier to use to create channel to proxy server.
  ///       this channel initializer pass request info and returns `EventLoopFuture<any Channel, Connection>`.
  public init(
    username: String,
    passwordReference: String,
    authenticationRequired: Bool,
    channelInitializer: @escaping @Sendable (Address) -> EventLoopFuture<NegotiationResult>
  ) {
    self.username = username
    self.passwordReference = passwordReference
    self.authenticationRequired = authenticationRequired
    self.channelInitializer = channelInitializer
  }

  public func handlerAdded(context: ChannelHandlerContext) {
    negotiationResultPromise = context.eventLoop.makePromise(of: NegotiationResult.self)
  }

  public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    var buffer = unwrapInboundIn(data)

    switch progress {
    case .waitingForGreeting(let byteBuffer):
      var byteBuffer = byteBuffer ?? context.channel.allocator.buffer(capacity: 3)
      byteBuffer.writeBuffer(&buffer)
      handleGreeting(context: context, data: byteBuffer)
    case .waitingForAuthorizing(var byteBuffer):
      byteBuffer.writeBuffer(&buffer)
      handleAuthorizing(context: context, data: byteBuffer)
    case .waitingForRequest(var byteBuffer):
      byteBuffer.writeBuffer(&buffer)
      handleRequest(context: context, data: byteBuffer)
    case .completed:
      eventBuffer.append(.channelRead(data: data))
    }
  }

  public func channelReadComplete(context: ChannelHandlerContext) {
    guard progress == .completed else {
      return
    }
    eventBuffer.append(.channelReadComplete)
  }

  private func handleGreeting(context: ChannelHandlerContext, data: ByteBuffer) {
    var byteBuffer = data
    guard let message = byteBuffer.readAuthenticationMethodRequest() else {
      progress = .waitingForGreeting(byteBuffer)
      return
    }

    guard message.version == .v5 else {
      negotiationResultPromise?.fail(SOCKSError.unsupportedProtocolVersion)
      channelClose(context: context, reason: SOCKSError.unsupportedProtocolVersion)
      return
    }

    // Choose authentication method
    let response: Authentication.Method.Response

    if authenticationRequired && message.methods.contains(.usernamePassword) {
      response = .init(method: .usernamePassword)
      progress = .waitingForAuthorizing(byteBuffer)
    } else if message.methods.contains(.noRequired) {
      response = .init(method: .noRequired)
      progress = .waitingForRequest(byteBuffer)
    } else {
      response = .init(method: .noAcceptable)
      // TODO: Error handling NO acceptable method.
    }

    var buffer = context.channel.allocator.buffer(capacity: 2)
    buffer.writeAuthenticationMethodResponse(response)

    context.writeAndFlush(wrapOutboundOut(buffer), promise: nil)
  }

  private func handleAuthorizing(context: ChannelHandlerContext, data: ByteBuffer) {
    var byteBuffer = data
    guard let authMsg = byteBuffer.readAuthenticationRequest() else {
      // Need more bytes to parse authentication message.
      progress = .waitingForAuthorizing(data)
      return
    }

    progress = .waitingForRequest(byteBuffer)

    let success = authMsg.username == username && authMsg.password == passwordReference

    var buffer = context.channel.allocator.buffer(capacity: 2)
    buffer.writeAuthenticationResponse(
      Authentication.UsernameAuthenticationResponse(status: success ? 0 : 1)
    )
    context.writeAndFlush(wrapOutboundOut(buffer), promise: nil)
  }

  private func handleRequest(context: ChannelHandlerContext, data: ByteBuffer) {
    do {
      var byteBuffer = data
      guard let details = try byteBuffer.readRequestDetails() else {
        progress = .waitingForRequest(data)
        return
      }

      let address = details.address

      let bs = NIOLoopBound(self, eventLoop: context.eventLoop)
      let ctx = NIOLoopBound(context, eventLoop: context.eventLoop)

      channelInitializer(address)
        .hop(to: context.eventLoop)
        .whenComplete {
          switch $0 {
          case .success(let negotiationResult):
            // FIXME: SOCKS5 response
            let response = Response(
              reply: .succeeded,
              boundAddress: .init(ctx.value.channel.localAddress!)
            )
            var buffer = ctx.value.channel.allocator.buffer(capacity: 16)
            buffer.writeServerResponse(response)
            ctx.value.writeAndFlush(bs.value.wrapOutboundOut(buffer), promise: nil)

            ctx.value.fireUserInboundEventTriggered(SOCKSUserEvent.handshakeCompleted)

            bs.value.negotiationResultPromise?.succeed(negotiationResult)
            bs.value.progress = .completed

            // Prepare data that need forward to next handler.
            if byteBuffer.readableBytes > 0 {
              byteBuffer.discardReadBytes()
              bs.value.eventBuffer.append(.channelRead(data: bs.value.wrapInboundOut(byteBuffer)))
            }
            ctx.value.pipeline.removeHandler(bs.value, promise: nil)
          case .failure(let error):
            let response: Response = .init(
              reply: .hostUnreachable,
              boundAddress: address
            )
            var buffer = ctx.value.channel.allocator.buffer(capacity: 16)
            buffer.writeServerResponse(response)
            ctx.value.writeAndFlush(bs.value.wrapOutboundOut(buffer), promise: nil)
            bs.value.negotiationResultPromise?.fail(error)
          }
        }
    } catch {
      negotiationResultPromise?.fail(error)
      channelClose(context: context, reason: error)
      return
    }
  }

  private func channelClose(context: ChannelHandlerContext, reason: Error) {
    context.fireErrorCaught(reason)
    context.close(promise: nil)
  }
}

extension SOCKS5ServerHandler: RemovableChannelHandler {

  public func removeHandler(
    context: ChannelHandlerContext,
    removalToken: ChannelHandlerContext.RemovalToken
  ) {
    while !eventBuffer.isEmpty {
      switch eventBuffer.removeFirst() {
      case .channelRead(let data):
        context.fireChannelRead(data)
      case .channelReadComplete:
        context.fireChannelReadComplete()
      }
    }

    if progress != .completed {
      negotiationResultPromise?.fail(ChannelError.inappropriateOperationForState)
    }

    context.leavePipeline(removalToken: removalToken)
  }
}

@available(*, unavailable)
extension SOCKS5ServerHandler: Sendable {}
