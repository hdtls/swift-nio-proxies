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

import NIOCore
import NIOHTTP1

/// HTTP request writer handler is a channel outbuond and removable handler whitch will send HTTP client request after handler added
/// to pipeline, and this handler also block all outbound writes and flush until handler removed, once handler removed all blocked writes
/// and flush will be delivered.
final public class HTTPRequestWriter: ChannelDuplexHandler, RemovableChannelHandler {

  public typealias InboundIn = NIOAny

  public typealias OutboundIn = NIOAny

  public typealias OutboundOut = NIOAny

  private typealias PendingWritesElement = (data: NIOAny, promise: EventLoopPromise<Void>?)

  private var pendingWrites: MarkedCircularBuffer<PendingWritesElement> = .init(initialCapacity: 1)

  private let host: String

  private let port: Int

  private var uri: String = "/"

  private var httpMethod: HTTPMethod = .GET

  private var additionalHTTPHeaders: [String: String] = [:]

  private var body: IOData?

  /// Initialize an instance of `HTTPRequestWriter` with specified host port uri mothod additional http headers and body.
  public init(
    host: String,
    port: Int,
    uri: String = "/",
    method: HTTPMethod = .GET,
    additionalHTTPHeaders: [String: String] = [:],
    body: IOData? = nil
  ) {
    self.host = host
    self.port = port
    self.uri = uri
    self.additionalHTTPHeaders = additionalHTTPHeaders
    self.body = body
  }

  public func handlerAdded(context: ChannelHandlerContext) {
    guard context.channel.isActive else { return }
    context.write(NIOAny(HTTPClientRequestPart.head(makeHTTPRequest())), promise: nil)
    let data = body ?? .byteBuffer(context.channel.allocator.buffer(capacity: 0))
    context.write(NIOAny(HTTPClientRequestPart.body(data)), promise: nil)
    context.write(NIOAny(HTTPClientRequestPart.end(nil)), promise: nil)
    context.flush()
  }

  public func channelActive(context: ChannelHandlerContext) {
    context.write(NIOAny(HTTPClientRequestPart.head(makeHTTPRequest())), promise: nil)
    let data = body ?? .byteBuffer(context.channel.allocator.buffer(capacity: 0))
    context.write(NIOAny(HTTPClientRequestPart.body(data)), promise: nil)
    context.write(NIOAny(HTTPClientRequestPart.end(nil)), promise: nil)
    context.flush()
    context.fireChannelActive()
  }

  public func handlerRemoved(context: ChannelHandlerContext) {
    guard context.channel.isWritable else { return }

    while pendingWrites.hasMark {
      let bufferedWrite = pendingWrites.removeFirst()
      context.write(bufferedWrite.data, promise: bufferedWrite.promise)
    }
    context.flush()

    while !pendingWrites.isEmpty {
      let bufferedWrite = pendingWrites.removeFirst()
      context.write(bufferedWrite.data, promise: bufferedWrite.promise)
    }
  }

  public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?)
  {
    pendingWrites.append((data, promise))
  }

  public func flush(context: ChannelHandlerContext) {
    pendingWrites.mark()
  }

  private func makeHTTPRequest() -> HTTPRequestHead {
    var headers = HTTPHeaders()
    headers.add(name: .host, value: "\(host):\(port)")
    if case .byteBuffer(let buffer) = body {
      headers.add(name: "Content-Length", value: "\(buffer.readableBytes)")
    }
    additionalHTTPHeaders.forEach { (key, value) in
      headers.replaceOrAdd(name: key, value: value)
    }
    return HTTPRequestHead(version: .http1_1, method: httpMethod, uri: uri, headers: headers)
  }
}
