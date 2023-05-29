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

import NEMisc
import NIOCore
import NIOHTTP1

/// A channel handler that wraps a channel for HTTP proxy.
/// This handler can be used in channels that are acting as the server in the HTTP proxy dialog.
final public class HTTPProxyServerHandler: ChannelInboundHandler, RemovableChannelHandler {

  public typealias InboundIn = HTTPServerRequestPart

  public typealias InboundOut = HTTPServerRequestPart

  public typealias OutboundOut = HTTPServerResponsePart

  private enum EventBuffer {
    case channelRead(data: NIOAny)
    case channelReadComplete
  }

  private enum Progress: Equatable {
    case waitingForData
    case waitingForComplete
    case completed
  }

  private var progress: Progress = .waitingForData

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
  private var eventBuffer: CircularBuffer<EventBuffer> = .init(initialCapacity: 2)

  /// The completion handler when proxy connection established.
  private let completion: @Sendable (RequestInfo) -> EventLoopFuture<Void>

  /// Initialize an instance of `HTTPProxyServerHandler` with specified parameters.
  ///
  /// - Parameters:
  ///   - username: Username for proxy authentication.
  ///   - passwordReference: Password for proxy authentication.
  ///   - authenticationRequired: A boolean value deterinse whether server should evaluate proxy authentication request.
  ///   - completion: The completion handler when proxy connection established, returns `EventLoopFuture<Void>` using given request info.
  public init(
    username: String,
    passwordReference: String,
    authenticationRequired: Bool,
    completion: @escaping @Sendable (RequestInfo) -> EventLoopFuture<Void>
  ) {
    self.username = username
    self.passwordReference = passwordReference
    self.authenticationRequired = authenticationRequired
    self.completion = completion
  }

  public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    guard progress == .waitingForData else {
      guard progress == .waitingForComplete else {
        context.fireChannelRead(data)
        return
      }
      // All inbound events will be buffered until handle remove from pipeline.
      eventBuffer.append(.channelRead(data: data))
      return
    }

    switch unwrapInboundIn(data) {
    case .head(let head) where progress == .waitingForData:
      headPart = head
      guard head.method != .CONNECT else {
        return
      }
      // Strip hop-by-hop header based on rfc2616.
      headPart.headers = headPart.headers.trimmingFieldsInHopByHop()
      eventBuffer.append(.channelRead(data: wrapInboundOut(.head(headPart))))
    case .body where headPart != nil && headPart.method != .CONNECT:
      eventBuffer.append(.channelRead(data: data))
    case .end where headPart != nil:
      progress = .waitingForComplete
      if headPart.method != .CONNECT {
        eventBuffer.append(.channelRead(data: data))
      }
      setupHTTPProxyPipeline(context: context)
    default:
      channelClose(context: context, reason: HTTPProxyError.invalidHTTPOrdering)
    }
  }

  public func channelReadComplete(context: ChannelHandlerContext) {
    eventBuffer.append(.channelReadComplete)
  }

  private func flushBuffers(context: ChannelHandlerContext) {
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

  private func authorize(message: HTTPHeaders.BasicAuthorization?, context: ChannelHandlerContext) {
    // Proxy Authorization
    if authenticationRequired {
      guard let authorization = message else {
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
  }

  private func setupHTTPProxyPipeline(context: ChannelHandlerContext) {
    guard let headPart else {
      channelClose(context: context, reason: HTTPProxyError.invalidHTTPOrdering)
      return
    }

    authorize(message: headPart.headers.proxyBasicAuthorization, context: context)

    let promise = context.eventLoop.makePromise(of: Void.self)

    if headPart.method == .CONNECT {
      context.pipeline.handler(type: ByteToMessageHandler<HTTPRequestDecoder>.self)
        .flatMap {
          context.pipeline.removeHandler($0)
        }
        .flatMapError { _ in
          context.eventLoop.makeSucceededVoidFuture()
        }
        .cascade(to: promise)
    } else {
      // For plain http proxy we need re-encode request to byte buffer.
      context.pipeline.addHandler(PlainHTTPRequestEncoder())
        .cascade(to: promise)
    }

    promise.futureResult
      .flatMap {
        self.completion(RequestInfo(address: .domainPort(host: headPart.host, port: headPart.port)))
      }
      .flatMap {
        let promise = context.eventLoop.makePromise(of: Void.self)
        // Only CONNECT tunnel need established response and remove default http server pipelines.
        if headPart.method == .CONNECT {
          // Ok, upgrade has completed! We now need to begin the upgrade process.
          // First, send the 200 connection established message.
          // This content-length header is MUST NOT, but we need to workaround NIO's insistence that
          // we set one.
          var headers = HTTPHeaders()
          headers.add(name: .contentLength, value: "0")
          let head = HTTPResponseHead(version: .http1_1, status: .ok, headers: headers)
          context.write(self.wrapOutboundOut(.head(head)), promise: nil)
          context.writeAndFlush(self.wrapOutboundOut(.end(nil)), promise: promise)
        } else {
          promise.succeed()
        }

        return promise.futureResult
      }
      .flatMap {
        context.pipeline.handler(type: HTTPResponseEncoder.self)
      }
      .flatMap {
        context.pipeline.removeHandler($0)
      }
      .flatMapError { _ in
        context.eventLoop.makeSucceededVoidFuture()
      }
      .whenComplete {
        switch $0 {
        case .success:
          self.progress = .completed
          self.flushBuffers(context: context)
          context.pipeline.removeHandler(self, promise: nil)
        case .failure(let error):
          self.channelClose(context: context, reason: error)
        }
      }
  }

  private func channelClose(context: ChannelHandlerContext, reason: Error) {
    var head: HTTPResponseHead?

    if let err = reason as? HTTPProxyError {
      switch err {
      case .invalidHTTPOrdering:
        head = HTTPResponseHead.init(version: .http1_1, status: .badRequest)
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
