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

import HTTPTypes
import NEAddressProcessing
import NIOCore
import NIOHTTPTypes

/// A channel handler that wraps a channel in HTTP CONNECT tunnel.
/// This handler can be used in channels that are acting as the client in the HTTP CONNECT tunnel proxy dialog.
final public class HTTPProxyClientHandler: ChannelDuplexHandler, RemovableChannelHandler {

  public typealias InboundIn = HTTPResponsePart

  public typealias OutboundIn = Never
  public typealias OutboundOut = HTTPRequestPart

  /// The credentials used to authenticate this proxy connection.
  private let passwordReference: String

  /// A boolean value deterinse whether client should perform proxy authentication.
  private let authenticationRequired: Bool

  /// The destination for this proxy connection.
  private let destinationAddress: Address

  /// States a handshake may be in
  private enum State {

    /// The initial state prior to start
    case setup

    /// Waiting are waiting for HTTP response data
    case waiting(Scheduled<Void>)

    /// Preparing are HTTP response head received
    case preparing(Scheduled<Void>)

    /// Ready are actively establishing the connection
    case ready

    /// Failed are failed to complete handshake.
    case failed(any Error)
  }

  private var state = State.setup

  private let additionalHTTPHandlers: [any RemovableChannelHandler]

  /// The HTTP proxy connection time out time amount.
  private let timeoutInterval: TimeAmount

  private typealias BufferedWrite = (data: NIOAny, promise: EventLoopPromise<Void>?)

  /// The circular buffer to buffer channel write before handshake established.
  ///
  /// All buffered write will unbuffered when proxy established.
  private var bufferedWrites: MarkedCircularBuffer<BufferedWrite>

  /// Return negotiation result future
  /// This future success once HTTP CONNECT negotiation success.
  public var negotiationResultFuture: EventLoopFuture<Void>? {
    negotiationResultPromise?.futureResult
  }
  private var negotiationResultPromise: EventLoopPromise<Void>?

  /// Initialize an instance of `HTTPProxyClientHandler` with specified parameters.
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
    negotiationResultPromise = context.eventLoop.makePromise()
    becomeActive(context: context)
  }

  public func handlerRemoved(context: ChannelHandlerContext) {
    switch state {
    case .setup, .waiting, .preparing:
      fail(
        error: NEHTTPError(code: .userCancelled, errorDescription: "EOF during handshake"),
        context: context)
    case .ready, .failed:
      break
    }
  }

  public func channelActive(context: ChannelHandlerContext) {
    context.fireChannelActive()
    becomeActive(context: context)
  }

  public func channelInactive(context: ChannelHandlerContext) {
    context.fireChannelInactive()
    switch state {
    case .setup:
      preconditionFailure("How can we receive a channelInactive before a channelActive?")
    case .waiting(let scheduled), .preparing(let scheduled):
      scheduled.cancel()
      fail(
        error: NEHTTPError(
          code: .channelInactive, errorDescription: "HTTP proxy client channel inactive"),
        context: context, close: false)
    case .ready, .failed:
      break
    }
  }

  public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    if case .ready = state {
      context.fireChannelRead(data)
      return
    }

    switch unwrapInboundIn(data) {
    case .head(let response):
      handleHTTPPartHead(response, context: context)
    case .body(let body):
      handleHTTPPartBody(body, context: context)
    case .end(let fields):
      handleHTTPPartEnd(fields, context: context)
    }
  }

  public func write(
    context: ChannelHandlerContext,
    data: NIOAny,
    promise: EventLoopPromise<Void>?
  ) {
    guard case .ready = state else {
      bufferedWrites.append((data, promise))
      return
    }
    context.write(data, promise: promise)
  }

  public func flush(context: ChannelHandlerContext) {
    // Unbuffer writes when handshake is success.
    guard case .ready = state else {
      bufferedWrites.mark()
      return
    }
    context.flush()
  }

  public func removeHandler(
    context: ChannelHandlerContext, removalToken: ChannelHandlerContext.RemovalToken
  ) {
    // We're being removed from the pipeline. If we have buffered events, deliver them.
    while bufferedWrites.hasMark {
      let bufferedWrite = bufferedWrites.removeFirst()
      context.write(bufferedWrite.data, promise: bufferedWrite.promise)
    }
    context.flush()

    while !bufferedWrites.isEmpty {
      let bufferedWrite = bufferedWrites.removeFirst()
      context.write(bufferedWrite.data, promise: bufferedWrite.promise)
    }

    context.leavePipeline(removalToken: removalToken)
  }
}

extension HTTPProxyClientHandler {

  private func becomeActive(context: ChannelHandlerContext) {
    guard case .setup = self.state else {
      // we might run into this handler twice, once in handlerAdded and once in channelActive.
      return
    }

    let timeout = context.eventLoop.scheduleTask(deadline: .now() + timeoutInterval) {
      switch self.state {
      case .setup:
        preconditionFailure(
          "How can we have a scheduled timeout, if the connection is not even up?")
      case .waiting:
        self.fail(error: NEHTTPError.requestTimeout, context: context)
      case .preparing, .ready, .failed:
        break
      }
    }

    self.state = .waiting(timeout)

    var uri = ""
    switch destinationAddress {
    case .hostPort:
      uri = "\(destinationAddress)"
    case .url(let url):
      if let host = url.host, let port = url.port {
        uri = "\(host):\(port)"
      } else {
        let error = NEHTTPError(
          code: .unsupportedAddress, errorDescription: "Invalid URL missing host or port")
        fail(error: error, context: context)
      }
    case .unix:
      let errorDescription = "Unix Domain Sockets don not support proxies"
      assertionFailure(errorDescription)
      let error = NEHTTPError(code: .unsupportedAddress, errorDescription: errorDescription)
      fail(error: error, context: context)
    }

    let httpFields = HTTPFields()
    var head = HTTPRequest(
      method: .connect, scheme: nil, authority: uri, path: nil, headerFields: httpFields)
    if authenticationRequired {
      head.headerFields[.proxyAuthorization] = passwordReference
    }

    context.write(wrapOutboundOut(.head(head)), promise: nil)
    context.write(wrapOutboundOut(.end(nil)), promise: nil)
    context.flush()
  }

  private func handleHTTPPartHead(_ response: HTTPResponse, context: ChannelHandlerContext) {
    guard case .waiting(let scheduled) = self.state else {
      preconditionFailure("HTTPDecoder should throw an error, if we have not send a request")
    }

    switch response.status {
    case _ where response.status.kind == .successful:
      // Any 2xx (Successful) response indicates that the sender (and all
      // inbound proxies) will switch to tunnel mode immediately after the
      // blank line that concludes the successful response's header section
      state = .preparing(scheduled)
    case .proxyAuthenticationRequired:
      fail(error: NEHTTPError.proxyAuthenticationRequired, context: context)
    default:
      // Any response other than a successful response indicates that the tunnel
      // has not yet been formed and that the connection remains governed by HTTP.
      fail(error: NEHTTPError(code: .unacceptableStatus(response.status)), context: context)
    }
  }

  private func handleHTTPPartBody(_ body: ByteBuffer?, context: ChannelHandlerContext) {
    switch state {
    case .setup, .waiting, .ready:
      let errorDescription = "Receive response body in invalid HTTP CONNECT handshake state"
      assertionFailure(errorDescription)
      fail(
        error: NEHTTPError(code: .unacceptableRead, errorDescription: errorDescription),
        context: context)
    case .preparing(let scheduled):
      // we don't expect a body on HTTP CONNECT.
      scheduled.cancel()
      fail(
        error: NEHTTPError(
          code: .unacceptableRead,
          errorDescription: "Receive response body in HTTP CONNECT handshaking"), context: context
      )
    case .failed:
      break
    }
  }

  private func handleHTTPPartEnd(_ fields: HTTPFields?, context: ChannelHandlerContext) {
    switch state {
    case .preparing(let scheduled):
      scheduled.cancel()
      EventLoopFuture.andAllSucceed(
        additionalHTTPHandlers.map {
          context.pipeline.removeHandler($0)
        }, on: context.eventLoop
      )
      .whenComplete {
        switch $0 {
        case .success:
          self.state = .ready
          self.negotiationResultPromise?.succeed()
          context.pipeline.removeHandler(context: context, promise: nil)
        case .failure(let error):
          self.fail(error: error, context: context)
        }
      }

    case .setup, .waiting, .ready:
      let errorDescription = "Receive response end in invalid HTTP CONNECT handshake state"
      assertionFailure(errorDescription)
      fail(
        error: NEHTTPError(code: .unacceptableRead, errorDescription: errorDescription),
        context: context)
    case .failed:
      break
    }
  }

  private func fail(error: any Error, context: ChannelHandlerContext, close: Bool = true) {
    negotiationResultPromise?.fail(error)
    state = .failed(error)
    context.fireErrorCaught(error)
    if close {
      context.close(mode: .all, promise: nil)
    }
  }
}

@available(*, unavailable)
extension HTTPProxyClientHandler: Sendable {}
