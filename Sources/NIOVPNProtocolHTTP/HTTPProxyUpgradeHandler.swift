//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright © 2019 Netbot Ltd. All rights reserved. and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIO
import NIOHTTP1

public class HTTPProxyUpgrader {

    public typealias ProxyHeadersEventLoop = (Channel, HTTPRequestHead, HTTPHeaders) -> EventLoopFuture<HTTPHeaders>
    public typealias ProxyUpgradeEventLoop = (ChannelHandlerContext, HTTPRequestHead) -> EventLoopFuture<Void>
    /// Builds the upgrade response headers. Should return any headers that need to be supplied to the client
    /// in the 101 Switching Protocols response. If upgrade cannot proceed for any reason, this function should
    /// fail the future.
    public let proxyHeadersEventLoop: ProxyHeadersEventLoop

    /// Called when the upgrade response has been flushed. At this time it is safe to mutate the channel pipeline
    /// to add whatever channel handlers are required. Until the returned `EventLoopFuture` succeeds, all received
    /// data will be buffered.
    public let proxyUpgradeEventLoop: (ChannelHandlerContext, HTTPRequestHead) -> EventLoopFuture<Void>

    public init(proxyHeadersEventLoop: @escaping ProxyHeadersEventLoop,
                proxyUpgradeEventLoop: @escaping ProxyUpgradeEventLoop) {
        self.proxyHeadersEventLoop = proxyHeadersEventLoop
        self.proxyUpgradeEventLoop = proxyUpgradeEventLoop
    }
}

/// A server-side channel handler that receives HTTP requests and optionally performs a HTTP-upgrade.
/// Removes itself from the channel pipeline after the first inbound request on the connection, regardless of
/// whether the upgrade succeeded or not.
///
/// This handler behaves a bit differently from its Netty counterpart because it does not allow upgrade
/// on any request but the first on a connection. This is primarily to handle clients that pipeline: it's
/// sufficiently difficult to ensure that the upgrade happens at a safe time while dealing with pipelined
/// requests that we choose to punt on it entirely and not allow it. As it happens this is mostly fine:
/// the odds of someone needing to upgrade midway through the lifetime of a connection are very low.
public final class HTTPProxyUpgradeHandler: ChannelInboundHandler, RemovableChannelHandler {
    public typealias InboundIn = HTTPServerRequestPart
    public typealias InboundOut = HTTPServerRequestPart
    public typealias OutboundOut = HTTPServerResponsePart

    private let httpEncoder: HTTPResponseEncoder
    private let extraHTTPHandlers: [RemovableChannelHandler]
    private let upgrader: HTTPProxyUpgrader

    /// Whether we've already seen the first request.
    private var needBuffer = false

    /// The closure that should be invoked when the end of the upgrade request is received if any.
    private var state: State = .setup

    /// The request head that should be asiged when the head of th request is received,
    private var head: HTTPRequestHead!

    /// The buffer data that have been readed when we're waiting for upgrade.
    private var buffer: CircularBuffer<NIOAny> = CircularBuffer()

    /// Create a `HTTPServerUpgradeHandler`.
    ///
    /// - Parameters:
    ///   - upgraders: All `HTTPServerProtocolUpgrader` objects that this pipeline will be able
    ///     to use to handle HTTP upgrade.
    ///   - httpEncoder: The `HTTPResponseEncoder` encoding responses from this handler and which will
    ///     be removed from the pipeline once the upgrade response is sent. This is used to ensure
    ///     that the pipeline will be in a clean state after upgrade.
    ///   - extraHTTPHandlers: Any other handlers that are directly related to handling HTTP. At the very least
    ///     this should include the `HTTPDecoder`, but should also include any other handler that cannot tolerate
    ///     receiving non-HTTP data.
    ///   - upgradeCompletionHandler: A block that will be fired when HTTP upgrade is complete.
    public init(httpEncoder: HTTPResponseEncoder,
                extraHTTPHandlers: [RemovableChannelHandler],
                upgrader: HTTPProxyUpgrader) {
        self.httpEncoder = httpEncoder
        self.extraHTTPHandlers = extraHTTPHandlers
        self.upgrader = upgrader
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard !needBuffer else {
            // We're waiting for upgrade to complete: buffer this data.
            self.buffer.append(data)
            return
        }

        let httpPart = unwrapInboundIn(data)

        switch state {
        case .setup:
            readHTTPHead(context: context, httpPart: httpPart)
        case .waiting:
            if case .end = httpPart {
                // This is the end of the first request, and we can upgrade. Time to kick it off.
                needBuffer = true
                applyHTTPUpgrade(context: context, head: head)
            }
        case .failure(let error):
            // We were re-entrantly called while delivering the request head. We can just pass this through.
            context.fireErrorCaught(error)
        case .ready:
            preconditionFailure("Upgrade has completed but we have not seen a whole request and still got re-entrantly called.")
        case .preparing:
            preconditionFailure("We think we saw .end before and began preparing, but somehow we have not set didReadProxyHead")
        }
    }

    private func readHTTPHead(context: ChannelHandlerContext, httpPart: HTTPServerRequestPart) {
        // We should decide if we're going to upgrade based on the first request header: if we aren't upgrading,
        // by the time the body comes in we should be out of the pipeline. That means that if we don't think we're
        // upgrading, the only thing we should see is a request head. Anything else in an error.
        guard case .head(let head) = httpPart else {
            state = .failure(HTTPServerUpgradeErrors.invalidHTTPOrdering)
            return
        }

        self.head = head
        state = .waiting
    }

    /// The core of the upgrade handling logic.
    ///
    /// - returns: An `EventLoopFuture` that will contain a callback to invoke if upgrade is requested,
    /// or nil if upgrade has failed. Never returns a failed future.
    private func applyHTTPUpgrade(context: ChannelHandlerContext, head: HTTPRequestHead) {
        // Ok, we're preparing.
        state = .preparing

        upgrader.proxyHeadersEventLoop(context.channel, head, buildEstablishedHTTPHeaders())
            .flatMap { httpHeaders in
                // Before we finish the upgrade we have to remove the HTTPDecoder and any other non-Encoder HTTP
                // handlers from the pipeline, to prevent them parsing any more data. We'll buffer the data until
                // that completes.
                // While there are a lot of Futures involved here it's quite possible that all of this code will
                // actually complete synchronously: we just want to program for the possibility that it won't.
                // Once that's done, we send the upgrade response, then remove the HTTP encoder, then call the
                // internal handler, then call the user code, and then finally when the user code is done we do
                // our final cleanup steps, namely we replay the received data we buffered in the meantime and
                // then remove ourselves from the pipeline.
                self.removeExtraHandlers(context: context).flatMap {
                    self.sendEstablish(context: context, head: head, httpHeaders: httpHeaders)
                }
            }
            .flatMap {
                context.pipeline.removeHandler(self.httpEncoder)
            }
            .flatMap {
                self.upgrader.proxyUpgradeEventLoop(context, head)
            }
            .map {
                self.state = .ready

                // We unbuffer any buffered data here and, if we sent any,
                // we also fire readComplete.
                let readComplete = self.buffer.count > 0
                while self.buffer.count > 0 {
                    let bufferedPart = self.buffer.removeFirst()
                    context.fireChannelRead(bufferedPart)
                }
                if readComplete {
                    context.fireChannelReadComplete()
                }
            }
            .whenComplete { _ in
                context.pipeline.removeHandler(context: context, promise: nil)
        }
    }

    /// Build establish response http headers
    private func buildEstablishedHTTPHeaders() -> HTTPHeaders {
        return HTTPHeaders([("Connection", "Established")])
    }

    /// Sends establish response for the pipeline.
    private func sendEstablish(context: ChannelHandlerContext,
                               head: HTTPRequestHead,
                               httpHeaders: HTTPHeaders) -> EventLoopFuture<Void> {
        let response = HTTPResponseHead(version: HTTPVersion(major: 1, minor: 1), status: .ok, headers: httpHeaders)
        context.write(wrapOutboundOut(.head(response)), promise: nil)
        return context.writeAndFlush(wrapOutboundOut(.end(nil)))
    }

    /// Removes any extra HTTP-related handlers from the channel pipeline.
    private func removeExtraHandlers(context: ChannelHandlerContext) -> EventLoopFuture<Void> {
        let futures = extraHTTPHandlers.map {
            context.pipeline.removeHandler($0)
        }
        return .andAllSucceed(futures, on: context.eventLoop)
    }
}

extension HTTPProxyUpgradeHandler {

    /// The state of the upgrade handler.
    private enum State {
        /// The initial state prior to start
        case setup

        /// The request head has been received. We're currently running the future chain waiting an upgrader.
        case waiting

        /// We have an upgrader, which means we can begin upgrade.
        case preparing

        /// The upgrade has succeeded, and we are being deliver buffered data and removed from the pipeline.
        case ready

        /// The upgrade has failed, and we are being removed from the pipeline.
        case failure(Error)
    }

    /// User events that may be fired by the `HTTPServerProtocolUpgrader`.
    private enum Events {
        /// Fired when HTTP upgrade has completed and the
        /// `HTTPServerProtocolUpgrader` is about to remove itself from the
        /// `ChannelPipeline`.
        case completed(result: HTTPRequestHead)
    }
}
