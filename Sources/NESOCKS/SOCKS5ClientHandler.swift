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

import NEAddressProcessing
import NIOCore

/// Connects to a SOCKS server to establish a proxied connection
/// to a host. This handler should be inserted at the beginning of a
/// channel's pipeline. Note that SOCKS only supports fully-qualified
/// domain names and IPv4 or IPv6 sockets, and not UNIX sockets.
final public class SOCKS5ClientHandler: ChannelDuplexHandler, RemovableChannelHandler {

  public typealias InboundIn = ByteBuffer
  public typealias InboundOut = ByteBuffer
  public typealias OutboundIn = ByteBuffer
  public typealias OutboundOut = ByteBuffer

  private var state: HandshakeState

  /// Buffered channel read buffer.
  private var readBuffer: ByteBuffer!

  /// Buffered channel writes.
  private var bufferedWrites: MarkedCircularBuffer<BufferedWrite> = .init(initialCapacity: 8)

  /// The removaltoken for RemovableChannelHandler.
  private var removalToken: ChannelHandlerContext.RemovalToken?

  /// The usename used to authenticate this proxy connection.
  private let username: String

  /// The password used to authenticate this proxy connection.
  private let passwordReference: String

  /// A boolean value deterinse whether server should evaluate proxy authentication request.
  private let authenticationRequired: Bool

  /// The destination address of the proxy request.
  private let destinationAddress: Address

  /// Creates a new `SOCKS5ClientHandler` that connects to a server
  /// and instructs the server to connect to `destinationAddress`.
  /// - Parameters:
  ///   - username: The username for username/password authentication,
  ///   - passwordReference: The password use for username/password authentication.
  ///   - authenticationRequired: A boolean value determinse whether should use username and password authentication.
  ///   - destinationAddress: The desired end point - note that only IPv4, IPv6, and FQDNs are supported.
  public init(
    username: String,
    passwordReference: String,
    authenticationRequired: Bool,
    destinationAddress: Address
  ) {
    guard case .hostPort = destinationAddress else {
      preconditionFailure("Initialize with \(destinationAddress) is not supported yet.")
    }

    self.username = username
    self.passwordReference = passwordReference
    self.authenticationRequired = authenticationRequired
    self.destinationAddress = destinationAddress
    self.state = .idle
    self.bufferedWrites = .init(initialCapacity: 6)
  }

  public func handlerAdded(context: ChannelHandlerContext) {
    if context.channel.isActive {
      startHandshaking(context: context)
    }
  }

  public func channelActive(context: ChannelHandlerContext) {
    context.fireChannelActive()
    startHandshaking(context: context)
  }

  public func channelRead(context: ChannelHandlerContext, data: NIOAny) {

    // if we've established the connection then forward on the data
    guard state != .established else {
      context.fireChannelRead(data)
      return
    }

    var byteBuffer = unwrapInboundIn(data)

    readBuffer.setOrWriteBuffer(&byteBuffer)

    switch state {
    case .greeting:
      receiveAuthenticationMethodResponse(context: context)
    case .authorizing:
      receiveAuthenticationResponse(context: context)
    case .addressing:
      receiveReplies(context: context)
    default:
      break
    }
  }

  public func write(
    context: ChannelHandlerContext,
    data: NIOAny,
    promise: EventLoopPromise<Void>?
  ) {
    bufferWrite(data: unwrapOutboundIn(data), promise: promise)
  }

  public func flush(context: ChannelHandlerContext) {
    bufferFlush()

    // Unbuffer writes when handshake is success.
    guard state == .established else {
      return
    }
    unbufferWrites(context: context)
  }

  public func removeHandler(
    context: ChannelHandlerContext,
    removalToken: ChannelHandlerContext.RemovalToken
  ) {
    precondition(context.handler === self)

    guard state == .established else {
      self.removalToken = removalToken
      return
    }

    flushBuffers(context: context)

    context.leavePipeline(removalToken: removalToken)
  }
}

extension SOCKS5ClientHandler {

  private typealias BufferedWrite = (data: ByteBuffer, promise: EventLoopPromise<Void>?)

  private func bufferWrite(data: ByteBuffer, promise: EventLoopPromise<Void>?) {
    guard data.readableBytes > 0 else {
      // We don't care about empty buffer.
      return
    }
    bufferedWrites.append((data: data, promise: promise))
  }

  private func bufferFlush() {
    bufferedWrites.mark()
  }

  private func unbufferWrites(context: ChannelHandlerContext) {
    while bufferedWrites.hasMark {
      let bufferedWrite = bufferedWrites.removeFirst()
      context.write(wrapOutboundOut(bufferedWrite.data), promise: bufferedWrite.promise)
    }
    context.flush()

    while !bufferedWrites.isEmpty {
      let bufferedWrite = bufferedWrites.removeFirst()
      context.write(wrapOutboundOut(bufferedWrite.data), promise: bufferedWrite.promise)
    }
  }

  private func flushBuffers(context: ChannelHandlerContext) {
    unbufferWrites(context: context)

    if let byteBuffer = readBuffer, byteBuffer.readableBytes > 0 {
      readBuffer = nil
      context.fireChannelRead(wrapInboundOut(byteBuffer))
    }
  }
}

extension SOCKS5ClientHandler {

  private func startHandshaking(context: ChannelHandlerContext) {
    precondition(state == .idle, "Invalid client state: \(state)")
    state = .greeting
    sendAuthenticationMethodRequest(context: context)
  }

  private func sendAuthenticationMethodRequest(context: ChannelHandlerContext) {
    // Authorization is performed when `authenticationRequired` is true.
    let method: Authentication.Method = authenticationRequired ? .usernamePassword : .noRequired

    let greeting = Authentication.Method.Request(methods: [method])

    // [version, #methods, methods...]
    let capacity = 3
    var buffer = context.channel.allocator.buffer(capacity: capacity)
    buffer.writeAuthenticationMethodRequest(greeting)

    context.writeAndFlush(wrapOutboundOut(buffer), promise: nil)
  }

  private func receiveAuthenticationMethodResponse(context: ChannelHandlerContext) {
    precondition(state == .greeting, "Invalid client state: \(state)")
    guard let authentication = readBuffer.readAuthenticationMethodResponse() else {
      return
    }

    guard authentication.version == .v5 else {
      state = .failed
      context.fireErrorCaught(SOCKSError.unsupportedProtocolVersion)
      channelClose(context: context, reason: SOCKSError.unsupportedProtocolVersion)
      return
    }

    switch authentication.method {
    case .noRequired:
      state = .addressing
      sendRequestDetails(context: context)
    case .usernamePassword:
      state = .authorizing
      sendAuthenticationRequest(context: context)
    case .noAcceptable:
      state = .failed
      context.fireErrorCaught(
        SOCKSError.authenticationFailed(reason: .noAcceptableMethod)
      )
      channelClose(
        context: context,
        reason: SOCKSError.authenticationFailed(reason: .noAcceptableMethod)
      )
    default:
      state = .failed
      context.fireErrorCaught(SOCKSError.authenticationFailed(reason: .unsupported))
      channelClose(
        context: context,
        reason: SOCKSError.authenticationFailed(reason: .unsupported)
      )
    }
  }

  private func sendAuthenticationRequest(context: ChannelHandlerContext) {
    let authentication = Authentication.UsernameAuthenticationRequest(
      username: username,
      password: passwordReference
    )

    let capacity = 3 + username.count + passwordReference.count
    var byteBuffer = context.channel.allocator.buffer(capacity: capacity)
    byteBuffer.writeAuthenticationRequest(authentication)

    context.writeAndFlush(wrapOutboundOut(byteBuffer), promise: nil)
  }

  private func receiveAuthenticationResponse(context: ChannelHandlerContext) {
    precondition(state == .authorizing, "Invalid client state: \(state)")
    guard let authMsg = readBuffer?.readAuthenticationResponse(), authMsg.isSuccess else {
      state = .failed
      context.fireErrorCaught(
        SOCKSError.authenticationFailed(reason: .badCredentials)
      )
      channelClose(
        context: context,
        reason: SOCKSError.authenticationFailed(reason: .badCredentials)
      )
      return
    }

    state = .addressing

    sendRequestDetails(context: context)
  }

  private func sendRequestDetails(context: ChannelHandlerContext) {
    let request = Request(command: .connect, address: destinationAddress)

    // the client request is always 6 bytes + the address info
    // [protocol_version, command, reserved, address type, <address>, port (2bytes)]
    let capacity = 6
    var buffer = context.channel.allocator.buffer(capacity: capacity)
    buffer.writeRequestDetails(request)
    context.writeAndFlush(wrapOutboundOut(buffer), promise: nil)
  }

  private func receiveReplies(context: ChannelHandlerContext) {
    precondition(state == .addressing, "Invalid client state: \(state)")
    let response: Response?

    do {
      response = try readBuffer.readServerResponse()
    } catch {
      context.fireErrorCaught(error)
      channelClose(context: context, reason: error)
      return
    }

    guard let response = response else {
      return
    }

    guard response.reply == .succeeded else {
      state = .failed
      context.fireErrorCaught(SOCKSError.replyFailed(reason: .parse(response.reply)))
      channelClose(
        context: context,
        reason: SOCKSError.replyFailed(reason: .parse(response.reply))
      )
      return
    }

    state = .established

    flushBuffers(context: context)

    context.fireUserInboundEventTriggered(SOCKSUserEvent.handshakeCompleted)

    if let removalToken = removalToken {
      context.leavePipeline(removalToken: removalToken)
    }
  }

  private func channelClose(context: ChannelHandlerContext, reason: Error) {
    context.close(promise: nil)
  }
}

/// A `Channel` user event that is sent when a SOCKS connection has been established
///
/// After this event has been received it is save to remove the `SOCKS5ClientHandler` from the channel pipeline.
public enum SOCKSUserEvent: Equatable, Sendable {
  case handshakeCompleted
}

@available(*, unavailable)
extension SOCKS5ClientHandler: Sendable {}
