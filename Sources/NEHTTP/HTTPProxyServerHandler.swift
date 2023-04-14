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

@_exported import NEMisc
@_exported import NIOCore
@_exported import NIOHTTP1

/// A channel handler that wraps a channel for HTTP proxy.
/// This handler can be used in channels that are acting as the server in the HTTP proxy dialog.
final public class HTTPProxyServerHandler: ChannelInboundHandler, RemovableChannelHandler {

  public typealias InboundIn = HTTPServerRequestPart
  public typealias InboundOut = HTTPServerRequestPart
  public typealias OutboundOut = HTTPServerResponsePart

  private enum Event {
    case channelRead(data: NIOAny)
    case channelReadComplete
  }

  private var state: ConnectionState

  /// The task request head part. this value is updated after `head` part received.
  private var headPart: HTTPRequestHead!

  /// The usename used to authenticate this proxy connection.
  private let username: String

  /// The password used to authenticate this proxy connection.
  private let passwordReference: String

  /// A boolean value deterinse whether server should evaluate proxy authentication request.
  private let authenticationRequired: Bool

  /// When a proxy request is received, we will send a new request to the target server.
  /// During the request is established, we need to buffer events.
  private var eventBuffer: CircularBuffer<Event> = .init(initialCapacity: 0)

  /// The `EventLoopFuture<Channel>` to used when creating outbound client channel.
  private var channelInitializer: (RequestInfo) -> EventLoopFuture<Channel>

  /// The completion handler when proxy connection established.
  private let completion: (RequestInfo, Channel, Channel) -> EventLoopFuture<Void>

  /// Initialize an instance of `HTTPProxyServerHandler` with specified parameters.
  ///
  /// - Parameters:
  ///   - username: Username for proxy authentication.
  ///   - passwordReference: Password for proxy authentication.
  ///   - authenticationRequired: A boolean value deterinse whether server should evaluate proxy authentication request.
  ///   - channelInitializer: The outbound channel initializer, returns the initialized outbound channel using the given request info.
  ///   - completion: The completion handler when proxy connection established, returns `EventLoopFuture<Void>` using given request info, server channel and outbound client channel.
  @preconcurrency
  public init(
    username: String,
    passwordReference: String,
    authenticationRequired: Bool,
    channelInitializer: @escaping @Sendable (RequestInfo) -> EventLoopFuture<Channel>,
    completion: @escaping @Sendable (RequestInfo, Channel, Channel) -> EventLoopFuture<Void>
  ) {
    self.username = username
    self.passwordReference = passwordReference
    self.authenticationRequired = authenticationRequired
    self.channelInitializer = channelInitializer
    self.completion = completion
    self.state = .idle
  }

  public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    guard state != .active else {
      // All inbound events will be buffered until handle remove from pipeline.
      eventBuffer.append(.channelRead(data: data))
      return
    }

    switch unwrapInboundIn(data) {
    case .head(let head) where state == .idle:
      headPart = head
      state = .handshaking
      guard head.method != .CONNECT else {
        return
      }
      // Strip hop-by-hop header based on rfc2616.
      headPart.headers = headPart.headers.trimmingFieldsInHopByHop()
      eventBuffer.append(.channelRead(data: wrapInboundOut(.head(headPart))))
      evaluateClientGreeting(context: context)
    case .body where headPart != nil && headPart.method != .CONNECT:
      eventBuffer.append(.channelRead(data: data))
    case .end where headPart != nil:
      guard headPart.method != .CONNECT else {
        evaluateClientGreeting(context: context)
        return
      }
      eventBuffer.append(.channelRead(data: data))
    default:
      channelClose(context: context, reason: HTTPProxyError.invalidHTTPOrdering)
    }
  }

  public func removeHandler(
    context: ChannelHandlerContext,
    removalToken: ChannelHandlerContext.RemovalToken
  ) {
    precondition(context.handler === self)
    guard state == .active else {

      return
    }

    flushBuffers(context: context)

    context.leavePipeline(removalToken: removalToken)
  }
}

extension HTTPProxyServerHandler {

  func flushBuffers(context: ChannelHandlerContext) {
    // We're being removed from the pipeline. If we have buffered events, deliver them.
    while !eventBuffer.isEmpty {
      switch eventBuffer.removeFirst() {
      case .channelRead(let data):
        context.fireChannelRead(data)
      case .channelReadComplete:
        context.fireChannelReadComplete()
      }
    }
  }
}

extension HTTPProxyServerHandler {

  private func evaluateClientGreeting(context: ChannelHandlerContext) {
    guard let head = headPart else {
      return
    }

    // Only CONNECT tunnel need remove default http server pipelines.
    if head.method == .CONNECT {
      // New request is complete. We don't want any more data from now on.
      _ = context.pipeline.handler(type: ByteToMessageHandler<HTTPRequestDecoder>.self)
        .flatMap {
          context.pipeline.removeHandler($0)
        }
    }

    // Proxy Authorization
    if authenticationRequired {
      guard let authorization = head.headers.proxyBasicAuthorization else {
        channelClose(
          context: context,
          reason: HTTPProxyError.unacceptableStatusCode(.proxyAuthenticationRequired)
        )
        return
      }

      guard username == authorization.username, passwordReference == authorization.password
      else {
        channelClose(
          context: context,
          reason: HTTPProxyError.unacceptableStatusCode(.unauthorized)
        )
        return
      }
    }

    let req = RequestInfo(address: .domainPort(host: head.host, port: head.port))

    self.channelInitializer(req).whenComplete {
      switch $0 {
      case .success(let channel):
        self.glue(req, with: channel, and: context)
      case .failure(let error):
        self.channelClose(context: context, reason: error)
      }
    }
  }

  private func glue(_ req: RequestInfo, with channel: Channel, and context: ChannelHandlerContext) {
    precondition(state == .handshaking, "invalid http order")

    let promise = context.eventLoop.makePromise(of: Void.self)

    // Only CONNECT tunnel need established response and remove default http server pipelines.
    if headPart.method == .CONNECT {
      // Ok, upgrade has completed! We now need to begin the upgrade process.
      // First, send the 200 connection established message.
      // This content-length header is MUST NOT, but we need to workaround NIO's insistence that we set one.
      var headers = HTTPHeaders()
      headers.add(name: .contentLength, value: "0")
      let head = HTTPResponseHead(version: .http1_1, status: .ok, headers: headers)
      context.write(wrapOutboundOut(.head(head)), promise: nil)
      context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)

      context.pipeline.handler(type: HTTPResponseEncoder.self)
        .flatMap {
          context.pipeline.removeHandler($0)
        }
        .cascade(to: promise)
    } else {
      promise.succeed(())
    }

    let (localGlue, peerGlue) = GlueHandler.matchedPair()
    promise.futureResult
      .flatMap {
        self.completion(req, context.channel, channel)
      }
      .flatMapThrowing {
        self.state = .active
        context.fireUserInboundEventTriggered(UserEvent.established(channel: channel))
        try context.pipeline.syncOperations.addHandler(localGlue)
        try channel.pipeline.syncOperations.addHandler(peerGlue)
      }
      .flatMap {
        context.pipeline.removeHandler(self)
      }
      .whenFailure { error in
        self.channelClose(context: context, reason: error)
      }
  }

  private func channelClose(context: ChannelHandlerContext, reason: Error) {
    var head: HTTPResponseHead?

    if let err = reason as? HTTPProxyError {
      switch err {
      case .invalidHTTPOrdering:
        head = HTTPResponseHead.init(version: .http1_1, status: .internalServerError)
      case .unacceptableStatusCode(let code):
        head = HTTPResponseHead.init(version: .http1_1, status: code)
      case .connectionTimedOut:
        break
      }
    }

    if let head = head {
      context.write(wrapOutboundOut(.head(head)), promise: nil)
      context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
    }

    context.fireErrorCaught(reason)
    context.close(promise: nil)
  }
}

@available(*, unavailable)
extension HTTPProxyServerHandler: Sendable {}

extension HTTPHeaders {

  /// Returns a new HTTPHeaders made by removing from all hop-by-hop fields.
  /// - Returns: The headers without hop-by-hop fields.
  func trimmingFieldsInHopByHop() -> HTTPHeaders {
    var headers = self
    headers.remove(name: .proxyConnection)
    headers.remove(name: .proxyAuthenticate)
    headers.remove(name: .proxyAuthorization)
    headers.remove(name: .te)
    headers.remove(name: .trailer)
    headers.remove(name: .transferEncoding)
    headers.remove(name: .upgrade)
    headers.remove(name: .connection)
    return headers
  }
}
