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

//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2017-2021 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import HTTPTypes
import NIOCore
import NIOHTTP1

/// The type of framing that is used to mark the end of the body.
private enum BodyFraming {
  case chunked
  case contentLength
  case neither
}

/// Adjusts the response/request headers to ensure that the response/request will be well-framed.
///
/// This method strips Content-Length and Transfer-Encoding headers from responses/requests that must
/// not have a body. It also adds Transfer-Encoding headers to responses/requests that do have bodies
/// but do not have any other transport headers when using HTTP/1.1. This ensures that we can
/// always safely reuse a connection.
///
/// Note that for HTTP/1.0 if there is no Content-Length then the response should be followed
/// by connection close. We require that the user send that connection close: we don't do it.
private func correctlyFrameTransportHeaders(
  hasBody: HTTPMethod.HasBody,
  headers: inout HTTPHeaders,
  version: HTTPVersion
) -> BodyFraming {
  switch hasBody {
  case .no:
    headers.remove(name: "content-length")
    headers.remove(name: "transfer-encoding")
    return .neither
  case .yes:
    if headers.contains(name: "content-length") {
      return .contentLength
    }
    if version.major == 1 && version.minor >= 1 {
      headers.replaceOrAdd(name: "transfer-encoding", value: "chunked")
      return .chunked
    } else {
      return .neither
    }
  case .unlikely:
    if headers.contains(name: "content-length") {
      return .contentLength
    }
    if version.major == 1 && version.minor >= 1 {
      return headers["transfer-encoding"].first == "chunked" ? .chunked : .neither
    }
    return .neither
  }
}

/// A channel handler that wraps a channel for HTTP proxy.
/// This handler can be used in channels that are acting as the server in the HTTP proxy dialog.
final public class HTTPProxyServerHandler<Connection>: ChannelInboundHandler,
  RemovableChannelHandler
{

  public typealias InboundIn = HTTPServerRequestPart

  public typealias OutboundOut = HTTPServerResponsePart

  public typealias NegotiationResult = (any Channel, Connection)

  private enum EventBuffer {
    case channelRead(data: NIOAny)
    case channelReadComplete
  }

  private enum State {
    /// The initial state prior to start
    case setup

    /// Waiting are waiting for HTTP request data.
    case waiting(HTTPVersion, HTTPRequest)

    /// Preparing are HTTP request data is received.
    case preparing(HTTPVersion, HTTPRequest)

    /// Ready are actively establishing the connection.
    case ready

    /// Failed are failed to complete handshake.
    case failed(any Error)
  }

  private var state = State.setup

  /// The credentials used to authenticate this proxy connection.
  private let passwordReference: String

  /// A boolean value deterinse whether server should evaluate proxy authentication request.
  private let authenticationRequired: Bool

  /// When a proxy request is received, we will send a new request to the target server.
  /// During the request is established, we need to buffer events.
  private var eventBuffer: CircularBuffer<EventBuffer> = .init(initialCapacity: 2)

  // A flag used to re-encode request (e.g. get proxy body).
  private var isChunked = false

  private let additionalHTTPHandlers: [any RemovableChannelHandler]

  public var negotiationResultFuture: EventLoopFuture<NegotiationResult> {
    guard let negotiationResultPromise else {
      preconditionFailure(
        "Tried to access the negotiation result before the handler was added to the pipeline"
      )
    }
    return negotiationResultPromise.futureResult
  }
  private var negotiationResultPromise: EventLoopPromise<NegotiationResult>?

  private let channelInitializer:
    @Sendable (HTTPVersion, HTTPRequest) -> EventLoopFuture<NegotiationResult>

  /// Initialize an instance of `HTTPProxyServerHandler` with specified parameters.
  ///
  /// - Parameters:
  ///   - passwordReference: Credentials for proxy authentication.
  ///   - authenticationRequired: A boolean value deterinse whether server should evaluate proxy authentication request.
  ///   - additionalHTTPHandlers: Additional HTTP handlers use for http codec.
  ///   - channelInitializer: The outbound channel initializer.
  public init(
    passwordReference: String,
    authenticationRequired: Bool,
    additionalHTTPHandlers: [any RemovableChannelHandler],
    channelInitializer: @escaping @Sendable (HTTPVersion, HTTPRequest) -> EventLoopFuture<
      NegotiationResult
    >
  ) {
    self.passwordReference = passwordReference
    self.authenticationRequired = authenticationRequired
    self.additionalHTTPHandlers = additionalHTTPHandlers
    self.channelInitializer = channelInitializer
  }

  public func handlerAdded(context: ChannelHandlerContext) {
    negotiationResultPromise = context.eventLoop.makePromise(of: NegotiationResult.self)
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

  public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    switch state {
    case .setup, .waiting:
      switch unwrapInboundIn(data) {
      case .head(let request):
        handleHTTPPartHead(request, context: context)
      case .body(let body):
        handleHTTPPartBody(body, context: context)
      case .end(let fields):
        handleHTTPPartEnd(fields, context: context)
      }
    case .preparing:
      eventBuffer.append(.channelRead(data: data))
    case .ready:
      context.fireChannelRead(data)
    case .failed:
      break
    }
  }

  public func channelReadComplete(context: ChannelHandlerContext) {
    guard case .ready = state else {
      eventBuffer.append(.channelReadComplete)
      return
    }
    context.fireChannelReadComplete()
  }

  /// Encode HTTP request into ByteBuffer, see HTTPRequestEncoder for more details.
  private func serializeHTTPPart(context: ChannelHandlerContext, _ httpPart: InboundIn)
    -> ByteBuffer
  {
    switch httpPart {
    case .head(var head):
      assert(
        !(head.headers.contains(name: "content-length")
          && head.headers[canonicalForm: "transfer-encoding"].contains("chunked"[...])),
        "illegal HTTP sent: \(head) contains both a content-length and transfer-encoding:chunked"
      )
      self.isChunked =
        correctlyFrameTransportHeaders(
          hasBody: head.method.hasRequestBody,
          headers: &head.headers,
          version: head.version
        ) == .chunked

      var buffer = context.channel.allocator.buffer(capacity: 256)
      buffer.writeHTTPRequestHead(head)
      buffer.writeHTTPHeaders(head.headers)

      return buffer
    case .body(let body):
      guard body.readableBytes > 0 else {
        return body
      }
      // we don't want to copy the chunk unnecessarily and therefore call write an annoyingly large number of times
      if isChunked {
        let readableBytes = body.readableBytes
        var data = context.channel.allocator.buffer(capacity: readableBytes + 32)
        var buffer = context.channel.allocator.buffer(capacity: 32)
        let len = String(readableBytes, radix: 16)
        buffer.writeString(len)
        buffer.writeStaticString(crlf)
        data.writeBuffer(&buffer)
        data.writeImmutableBuffer(body)

        // Just move the buffers readerIndex to only make the \r\n readable and depend on COW semantics.
        buffer.moveReaderIndex(forwardBy: buffer.readableBytes - 2)
        data.writeBuffer(&buffer)
        return data
      } else {
        return body
      }
    case .end(let trailers):
      guard isChunked else {
        return context.channel.allocator.buffer(capacity: 0)
      }

      var buffer: ByteBuffer
      if let trailers {
        buffer = context.channel.allocator.buffer(capacity: 256)
        buffer.writeStaticString("0")
        buffer.writeStaticString(crlf)
        buffer.writeHTTPHeaders(trailers)  // Includes trailing CRLF.
      } else {
        buffer = context.channel.allocator.buffer(capacity: 8)
        buffer.writeStaticString("0")
        buffer.writeStaticString(crlf)
        buffer.writeStaticString(crlf)
      }
      return buffer
    }
  }

  public func removeHandler(
    context: ChannelHandlerContext,
    removalToken: ChannelHandlerContext.RemovalToken
  ) {
    // We're being removed from the pipeline. If we have buffered events, deliver them.
    while !eventBuffer.isEmpty {
      switch eventBuffer.removeFirst() {
      case .channelRead(let data):
        context.fireChannelRead(data)
      case .channelReadComplete:
        context.fireChannelReadComplete()
      }
    }

    context.leavePipeline(removalToken: removalToken)
  }
}

extension HTTPProxyServerHandler {

  private func handleHTTPPartHead(_ request: HTTPRequestHead, context: ChannelHandlerContext) {
    do {
      var head = request
      let originalHTTPRequest: HTTPRequest
      if head.method == .CONNECT {
        originalHTTPRequest = try HTTPRequest(head)
      } else {
        // Strip hop-by-hop header based on rfc2616.
        head.headers.trimmingHopByHopFields()
        originalHTTPRequest = try HTTPRequest(head)
        let data = serializeHTTPPart(context: context, .head(head))
        eventBuffer.append(.channelRead(data: NIOAny(data)))
      }
      state = .waiting(head.version, originalHTTPRequest)
    } catch {
      fail(
        error: NEHTTPError(code: .badRequest, errorDescription: error.localizedDescription),
        context: context)
    }
  }

  private func handleHTTPPartBody(_ body: ByteBuffer, context: ChannelHandlerContext) {
    guard case .waiting(_, let originalHTTPRequest) = state else {
      let errorDescription = "Receive request body in invalid HTTP CONNECT handshake state"
      preconditionFailure(errorDescription)
    }

    guard originalHTTPRequest.method != .connect else {
      let errorDescription = "Receive request body in invalid HTTP CONNECT handshaking"
      fail(
        error: NEHTTPError(code: .badRequest, errorDescription: errorDescription),
        context: context)
      return
    }

    let data = serializeHTTPPart(context: context, .body(body))
    eventBuffer.append(.channelRead(data: NIOAny(data)))
  }

  private func handleHTTPPartEnd(_ fields: HTTPHeaders?, context: ChannelHandlerContext) {
    guard case .waiting(let originalHTTPVersion, let originalHTTPRequest) = state else {
      let errorDescription = "Receive request body in invalid HTTP CONNECT handshake state"
      preconditionFailure(errorDescription)
    }

    state = .preparing(originalHTTPVersion, originalHTTPRequest)

    if originalHTTPRequest.method != .connect {
      let data = serializeHTTPPart(context: context, .end(fields))
      eventBuffer.append(.channelRead(data: NIOAny(data)))
    }
    configureHTTPTunnelPipeline(context: context)
  }

  private func configureHTTPTunnelPipeline(context: ChannelHandlerContext) {
    guard case .preparing(let originalHTTPVersion, let originalHTTPRequest) = state else {
      let errorDescription = "Configure HTTP tunnel in invalid HTTP CONNECT handshake state"
      preconditionFailure(errorDescription)
    }

    guard authenticate(context: context, connection: originalHTTPRequest) else {
      return
    }

    channelInitializer(originalHTTPVersion, originalHTTPRequest)
      .hop(to: context.eventLoop)
      .flatMap { negotiationResult in
        // Only CONNECT tunnel need established response and remove default http server pipelines.
        if originalHTTPRequest.method == .connect {
          // Ok, upgrade has completed! We now need to begin the upgrade process.
          // First, send the 200 connection established message.
          // This content-length header is MUST NOT, but we need to workaround NIO's insistence that
          // we set one.
          let headers = HTTPHeaders([("Content-Length", "0")])
          let head = HTTPResponseHead(version: originalHTTPVersion, status: .ok, headers: headers)
          let data = NIOAny(HTTPServerResponsePart.head(head))

          // We don't flush data until we remove all additional http handlers.
          context.write(data, promise: nil)
        }

        return EventLoopFuture.andAllSucceed(
          self.additionalHTTPHandlers.map { context.pipeline.removeHandler($0) },
          on: context.eventLoop
        )
        .map { _ in negotiationResult }
      }
      .whenComplete {
        switch $0 {
        case .success(let negotiationResult):
          // After all additional http handlers removed, we should flush our response.
          context.flush()
          self.state = .ready
          self.negotiationResultPromise?.succeed(negotiationResult)

          // Handshake is completed and we can remove handler and unbuffer all reads.
          context.pipeline.removeHandler(context: context, promise: nil)
        case .failure(let error):
          self.fail(error: error, context: context)
        }
      }
  }

  private func authenticate(context: ChannelHandlerContext, connection: HTTPRequest) -> Bool {
    guard authenticationRequired else {
      return true
    }

    guard connection.headerFields[.proxyAuthorization] != passwordReference else {
      return true
    }
    fail(error: NEHTTPError.proxyAuthenticationRequired, context: context)
    return false
  }

  private func fail(error: any Error, context: ChannelHandlerContext, close: Bool = true) {
    negotiationResultPromise?.fail(error)
    state = .failed(error)

    defer {
      context.fireErrorCaught(error)
      if close {
        context.close(mode: .all, promise: nil)
      }
    }

    guard let error = error as? NEHTTPError else {
      return
    }

    var status: HTTPResponseStatus?
    var httpFields = HTTPHeaders()
    switch error.code {
    case .badRequest:
      status = .badRequest
      httpFields = ["Connection": "close", "Content-Length": "0"]
    case .proxyAuthenticationRequired:
      status = .proxyAuthenticationRequired
      httpFields = ["Connection": "close", "Content-Length": "0"]
    case .requestTimeout:
      status = .requestTimeout
      httpFields = ["Connection": "close", "Content-Length": "0"]
    default:
      break
    }

    guard let status else {
      return
    }

    let head = HTTPResponseHead(
      version: .http1_1,
      status: status,
      headers: httpFields
    )
    context.write(wrapOutboundOut(.head(head)), promise: nil)
    context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
  }
}

@available(*, unavailable)
extension HTTPProxyServerHandler: Sendable {}
