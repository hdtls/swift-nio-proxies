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

/// A channel handler that wraps a channel in HTTP CONNECT tunnel.
/// This handler can be used in channels that are acting as the client in the HTTP CONNECT tunnel proxy dialog.
final public class HTTP1ClientCONNECTTunnelHandler: ChannelDuplexHandler, RemovableChannelHandler {

  public typealias InboundIn = HTTPClientResponsePart
  public typealias OutboundIn = NIOAny

  /// The usename used to authenticate this proxy connection.
  private let username: String

  /// The password used to authenticate this proxy connection.
  private let passwordReference: String

  /// A boolean value deterinse whether client should perform proxy authentication.
  private let authenticationRequired: Bool

  /// A boolean value determinse whether client should use HTTP CONNECT tunnel to proxy connection.
  private let preferHTTPTunneling: Bool

  /// The destination for this proxy connection.
  private let destinationAddress: NetAddress

  private var state: ConnectionState

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
  ///   - username: Username for proxy authentication.
  ///   - passwordReference: Password for proxy authentication.
  ///   - authenticationRequired: A boolean value deterinse whether client should perform proxy authentication.
  ///   - preferHTTPTunneling: A boolean value determinse whether client should use HTTP CONNECT tunnel to proxy connection.
  ///   - destinationAddress: The destination for this proxy connection.
  ///   - timeout: A TimeAmount use to calculate deadline for handshaking timeout. The default timeout interval is 60 seconds.
  public init(
    username: String,
    passwordReference: String,
    authenticationRequired: Bool,
    preferHTTPTunneling: Bool,
    destinationAddress: NetAddress,
    timeoutInterval: TimeAmount = .seconds(60)
  ) {
    self.username = username
    self.passwordReference = passwordReference
    self.authenticationRequired = authenticationRequired
    self.preferHTTPTunneling = preferHTTPTunneling
    self.destinationAddress = destinationAddress
    self.state = .idle
    self.bufferedWrites = .init(initialCapacity: 6)
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
    guard state != .active else {
      context.fireChannelRead(data)
      return
    }

    switch (unwrapInboundIn(data), state) {
    case (.head(let head), .handshaking):
      if !(200..<300).contains(head.status.code) {
        scheduled?.cancel()
        state = .failed
        channelClose(
          context: context,
          reason: HTTPProxyError.unacceptableStatusCode(head.status)
        )
      }
    case (.body, .handshaking):
      break
    case (.end, .handshaking):
      established(context: context)
    default:
      scheduled?.cancel()
      channelClose(context: context, reason: HTTPProxyError.invalidHTTPOrdering)
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
    guard state == .active else {
      return
    }
    unbufferWrites(context: context)
  }
}

extension HTTP1ClientCONNECTTunnelHandler {

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
}

extension HTTP1ClientCONNECTTunnelHandler {

  /// Sending HTTP CONNECT request to proxy server and perform a timeout schedule task.
  private func performCONNECTHandshake(context: ChannelHandlerContext) {
    guard context.channel.isActive, state == .idle else {
      return
    }

    scheduled = context.eventLoop.scheduleTask(in: timeoutInterval) {
      switch self.state {
      case .idle:
        preconditionFailure(
          "How can we have a scheduled timeout, if the connection is not even up?"
        )
      case .handshaking:
        self.channelClose(context: context, reason: HTTPProxyError.connectionTimedOut)
      case .active, .failed:
        break
      }
    }

    state = .handshaking

    let uri: String
    switch destinationAddress {
    case .domainPort(let domain, let port):
      uri = "\(domain):\(port)"
    case .socketAddress(let socketAddress):
      guard let host = socketAddress.ipAddress, let port = socketAddress.port else {
        channelClose(context: context, reason: SocketAddressError.unsupported)
        return
      }
      uri = "\(host):\(port)"
    }

    var head: HTTPRequestHead = .init(version: .http1_1, method: .CONNECT, uri: uri)
    if authenticationRequired {
      head.headers.proxyBasicAuthorization = .init(
        username: username,
        password: passwordReference
      )
    }

    context.write(NIOAny(HTTPClientRequestPart.head(head)), promise: nil)
    context.writeAndFlush(NIOAny(HTTPClientRequestPart.end(nil)), promise: nil)
  }

  private func established(context: ChannelHandlerContext) {
    context.pipeline.handler(type: HTTPRequestEncoder.self)
      .flatMap {
        context.pipeline.removeHandler($0)
      }
      .flatMap {
        context.pipeline.handler(type: ByteToMessageHandler<HTTPResponseDecoder>.self)
      }
      .flatMap {
        context.pipeline.removeHandler($0)
      }
      .flatMap {
        context.pipeline.handler(type: NIOHTTPRequestHeadersValidator.self)
      }
      .flatMap {
        context.pipeline.removeHandler($0)
      }
      .whenComplete {
        switch $0 {
        case .success:
          self.state = .active
          self.unbufferWrites(context: context)
          self.scheduled?.cancel()
          context.fireUserInboundEventTriggered(
            UserEvent.established(channel: context.channel)
          )
          context.pipeline.removeHandler(self, promise: nil)
        case .failure(let error):
          self.channelClose(context: context, reason: error)
        }
      }
  }

  private func channelClose(context: ChannelHandlerContext, reason: Error) {
    context.fireErrorCaught(reason)
    context.close(promise: nil)
  }
}

#if swift(>=5.7)
@available(*, unavailable)
extension HTTP1ClientCONNECTTunnelHandler: Sendable {}
#endif