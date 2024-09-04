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
final public class HTTPProxyServerHandler: ChannelInboundHandler, RemovableChannelHandler {

  public typealias InboundIn = HTTPServerRequestPart

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
  private var originalHTTPRequest: HTTPRequest?

  /// The task request version. this value is updated after `head` part received.
  private var originalHTTPVersion = HTTPVersion.http1_1

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

  /// The completion handler when proxy connection established.
  private let completion: @Sendable (HTTPVersion, HTTPRequest) -> EventLoopFuture<Void>

  /// Initialize an instance of `HTTPTunnelSVRHandler` with specified parameters.
  ///
  /// - Parameters:
  ///   - passwordReference: Credentials for proxy authentication.
  ///   - authenticationRequired: A boolean value deterinse whether server should evaluate proxy authentication request.
  ///   - additionalHTTPHandlers: Additional HTTP handlers use for http codec.
  ///   - completion: The completion handler when proxy connection established, returns `EventLoopFuture<Void>` using given request info.
  public init(
    passwordReference: String,
    authenticationRequired: Bool,
    additionalHTTPHandlers: [any RemovableChannelHandler],
    completion: @escaping @Sendable (HTTPVersion, HTTPRequest) -> EventLoopFuture<Void>
  ) {
    self.passwordReference = passwordReference
    self.authenticationRequired = authenticationRequired
    self.additionalHTTPHandlers = additionalHTTPHandlers
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
    case .head(var head) where progress == .waitingForData:
      do {
        originalHTTPVersion = head.version

        if head.method == .CONNECT {
          originalHTTPRequest = try HTTPRequest(head)
        } else {
          // Strip hop-by-hop header based on rfc2616.
          head.headers.trimmingHopByHopFields()
          originalHTTPRequest = try HTTPRequest(head)
          let data = serializeHTTPPart(context: context, .head(head))
          eventBuffer.append(.channelRead(data: NIOAny(data)))
        }
      } catch {
        channelClose(context: context, reason: error)
      }
    case .body(let bodyPart)
    where originalHTTPRequest != nil && originalHTTPRequest?.method != .connect:
      let data = serializeHTTPPart(context: context, .body(bodyPart))
      eventBuffer.append(.channelRead(data: NIOAny(data)))
    case .end(let trailers) where originalHTTPRequest != nil:
      progress = .waitingForComplete
      if originalHTTPRequest?.method != .connect {
        let data = serializeHTTPPart(context: context, .end(trailers))
        eventBuffer.append(.channelRead(data: NIOAny(data)))
      }
      configureHTTPTunnelPipeline(context: context)
    default:
      channelClose(context: context, reason: HTTPProxyError.invalidHTTPOrdering)
    }
  }

  public func channelReadComplete(context: ChannelHandlerContext) {
    eventBuffer.append(.channelReadComplete)
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

  private func authenticate(context: ChannelHandlerContext, connection: HTTPRequest) {
    guard authenticationRequired else {
      return
    }

    guard connection.headerFields[values: .proxyAuthorization].contains(passwordReference) else {
      channelClose(
        context: context,
        reason: HTTPProxyError.unacceptableStatusCode(.proxyAuthenticationRequired)
      )
      return
    }
  }

  private func configureHTTPTunnelPipeline(context: ChannelHandlerContext) {
    guard let originalHTTPRequest else {
      channelClose(context: context, reason: HTTPProxyError.invalidHTTPOrdering)
      return
    }
    authenticate(context: context, connection: originalHTTPRequest)

    let bs = NIOLoopBound(self, eventLoop: context.eventLoop)
    let ctx = NIOLoopBound(context, eventLoop: context.eventLoop)

    let originalHTTPVersion = self.originalHTTPVersion
    completion(originalHTTPVersion, originalHTTPRequest)
      .hop(to: context.eventLoop)
      .flatMap {
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
          ctx.value.write(data, promise: nil)
        }

        // Remove all additional http handlers, so we can receive original request data.
        let futures = bs.value.additionalHTTPHandlers.map {
          ctx.value.pipeline.removeHandler($0)
            .flatMapError { error in
              // We don't want handler not found error interrupt our stream, because handlers may
              // be removed by user outside this handler.
              guard case .notFound = error as? ChannelPipelineError else {
                return ctx.value.eventLoop.makeFailedFuture(error)
              }
              return ctx.value.eventLoop.makeSucceededVoidFuture()
            }
        }
        return .andAllSucceed(futures, on: ctx.value.eventLoop)
      }
      .whenComplete {
        switch $0 {
        case .success:
          // After all additional http handlers removed, we should flush our response.
          ctx.value.flush()

          bs.value.progress = .completed
          // We're being removed from the pipeline. If we have buffered events, deliver them.
          while !bs.value.eventBuffer.isEmpty {
            switch bs.value.eventBuffer.removeFirst() {
            case .channelRead(let data):
              ctx.value.fireChannelRead(data)
            case .channelReadComplete:
              ctx.value.fireChannelReadComplete()
            }
          }
          ctx.value.pipeline.removeHandler(bs.value, promise: nil)
        case .failure(let error):
          bs.value.channelClose(context: ctx.value, reason: error)
        }
      }
  }

  private func channelClose(context: ChannelHandlerContext, reason: Error) {
    var head: HTTPResponseHead?

    if let err = reason as? HTTPProxyError {
      switch err {
      case .invalidHTTPOrdering:
        head = HTTPResponseHead(version: originalHTTPVersion, status: .badRequest)
      case .unacceptableStatusCode(let code):
        head = HTTPResponseHead(version: originalHTTPVersion, status: code)
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
