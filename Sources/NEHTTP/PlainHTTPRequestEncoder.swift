//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2023 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

@_exported import NIOCore
@_exported import NIOHTTP1

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

final public class PlainHTTPRequestEncoder: ChannelInboundHandler, RemovableChannelHandler {

  public typealias InboundIn = HTTPServerRequestPart

  public typealias InboundOut = ByteBuffer

  private var isChunked = false

  public init() {}

  public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    switch unwrapInboundIn(data) {
    case .head(var request):
      assert(
        !(request.headers.contains(name: "content-length")
          && request.headers[canonicalForm: "transfer-encoding"].contains("chunked"[...])),
        "illegal HTTP sent: \(request) contains both a content-length and transfer-encoding:chunked"
      )
      self.isChunked =
        correctlyFrameTransportHeaders(
          hasBody: request.method.hasRequestBody,
          headers: &request.headers,
          version: request.version
        ) == .chunked

      var buffer = context.channel.allocator.buffer(capacity: 256)
      buffer.writeHTTPRequestHead(request)
      buffer.writeHTTPHeaders(request.headers)
      context.fireChannelRead(wrapInboundOut(buffer))
    case .body(let bodyPart):
      guard bodyPart.readableBytes > 0 else {
        // Empty writes shouldn't send any bytes in chunked or identity encoding.
        context.fireChannelRead(wrapInboundOut(bodyPart))
        return
      }
      let readableBytes = bodyPart.readableBytes

      // we don't want to copy the chunk unnecessarily and therefore call write an annoyingly large number of times
      if isChunked {
        var buffer = context.channel.allocator.buffer(capacity: 32)
        let len = String(readableBytes, radix: 16)
        buffer.writeString(len)
        buffer.writeStaticString(crlf)
        context.fireChannelRead(wrapInboundOut(buffer))
        context.fireChannelRead(wrapInboundOut(bodyPart))

        // Just move the buffers readerIndex to only make the \r\n readable and depend on COW semantics.
        buffer.moveReaderIndex(forwardBy: buffer.readableBytes - 2)
        context.fireChannelRead(wrapInboundOut(buffer))
      } else {
        context.fireChannelRead(wrapInboundOut(bodyPart))
      }
    case .end(let trailers):
      var buffer: ByteBuffer
      if isChunked {
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
      } else {
        buffer = context.channel.allocator.buffer(capacity: 0)
      }
      context.fireChannelRead(wrapInboundOut(buffer))
    }
  }
}

@available(*, unavailable)
extension PlainHTTPRequestEncoder: Sendable {}
