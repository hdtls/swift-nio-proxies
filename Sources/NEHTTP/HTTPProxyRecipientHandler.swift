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

import HTTPTypes
import NIOCore
import NIOHTTP1
import NIOHTTPTypes
import NIOHTTPTypesHTTP1

/// A channel handler that wraps a channel for HTTP proxy.
/// This handler can be used in channels that are acting as the server in the HTTP proxy dialog.
final public class HTTPProxyRecipientHandelr: ChannelInboundHandler, RemovableChannelHandler {
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

  private var httpVersion: HTTPVersion = .http1_1

  /// The task request head part. this value is updated after `head` part received.
  private var httpRequest: HTTPRequest!

  /// The credentials used to authenticate this proxy connection.
  private let passwordReference: String

  /// A boolean value deterinse whether server should evaluate proxy authentication request.
  private let authenticationRequired: Bool

  /// When a proxy request is received, we will send a new request to the target server.
  /// During the request is established, we need to buffer events.
  private var eventBuffer: CircularBuffer<EventBuffer> = .init(initialCapacity: 2)

  /// The completion handler when proxy connection established.
  private let completion: @Sendable (HTTPVersion, HTTPRequest) -> EventLoopFuture<Void>

  /// Initialize an instance of `HTTPProxyRecipientHandelr` with specified parameters.
  ///
  /// - Parameters:
  ///   - username: Username for proxy authentication.
  ///   - passwordReference: Credentials for proxy authentication.
  ///   - authenticationRequired: A boolean value deterinse whether server should evaluate proxy authentication request.
  ///   - completion: The completion handler when proxy connection established, returns `EventLoopFuture<Void>` using given request info.
  public init(
    passwordReference: String,
    authenticationRequired: Bool,
    completion: @escaping @Sendable (HTTPVersion, HTTPRequest) -> EventLoopFuture<Void>
  ) {
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
      do {
        httpRequest = try HTTPRequest(head, secure: head.method == .CONNECT, splitCookie: true)
        httpVersion = head.version
        guard httpRequest.method != .connect else {
          return
        }
        // Strip hop-by-hop header based on rfc2616.
        httpRequest.headerFields.trimmingHopByHopFields()
        var head = try HTTPRequestHead(httpRequest)
        head.version = httpVersion
        eventBuffer.append(.channelRead(data: wrapInboundOut(.head(head))))
      } catch {
        context.fireErrorCaught(error)
      }
    case .body where httpRequest != nil && httpRequest.method != .connect:
      eventBuffer.append(.channelRead(data: data))
    case .end where httpRequest != nil:
      progress = .waitingForComplete
      if httpRequest.method != .connect {
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

  private func authenticate(connection: HTTPRequest) throws {
    guard authenticationRequired else {
      return
    }

    guard !passwordReference.isEmpty else {
      throw HTTPProxyError.unacceptableStatusCode(.proxyAuthenticationRequired)
    }

    if !connection.headerFields[values: .proxyAuthorization].contains(passwordReference) {
      throw HTTPProxyError.unacceptableStatusCode(.proxyAuthenticationRequired)
    }
  }

  private func setupHTTPProxyPipeline(context: ChannelHandlerContext) {
    guard let httpRequest else {
      channelClose(context: context, reason: HTTPProxyError.invalidHTTPOrdering)
      return
    }

    do {
      try authenticate(connection: httpRequest)
    } catch {
      channelClose(context: context, reason: error)
    }

    let promise = context.eventLoop.makePromise(of: Void.self)

    if httpRequest.method == .connect {
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
        self.completion(self.httpVersion, httpRequest)
      }
      .flatMap {
        let promise = context.eventLoop.makePromise(of: Void.self)
        // Only CONNECT tunnel need established response and remove default http server pipelines.
        if httpRequest.method == .connect {
          // Ok, upgrade has completed! We now need to begin the upgrade process.
          // First, send the 200 connection established message.
          // This content-length header is MUST NOT, but we need to workaround NIO's insistence that
          // we set one.
          var headers = HTTPHeaders()
          headers.add(name: "Content-Length", value: "0")
          let head = HTTPResponseHead(version: self.httpVersion, status: .ok, headers: headers)
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
        head = HTTPResponseHead(version: httpVersion, status: .badRequest)
      case .unacceptableStatusCode(let code):
        head = HTTPResponseHead(version: httpVersion, status: code)
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
extension HTTPProxyRecipientHandelr: Sendable {}
