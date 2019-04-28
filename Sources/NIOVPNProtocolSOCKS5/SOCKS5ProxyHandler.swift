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

import Foundation
import NIO

/// A basic username and password.
public struct BasicAuthorization {
    /// The username, sometimes an email address
    public let username: String

    /// The plaintext password
    public let password: String

    /// Create a new `BasicAuthorization`.
    public init(username: String, password: String) {
        self.username = username
        self.password = password
    }

    /// Returns a base64 encoded basic authentication credential as an authorization header tuple.
    ///
    /// - parameter user:     The user.
    /// - parameter password: The password.
    ///
    /// - returns: A tuple with Authorization header and credential value if encoding succeeds, `nil` otherwise.
    public var authorizationHeader: (key: String, value: String)? {
        guard let data = "\(username):\(password)".data(using: .utf8) else { return nil }

        let credential = data.base64EncodedString(options: [])

        return (key: "Authorization", value: "Basic \(credential)")
    }
}

/// SOCKS Proxy configuation
public struct ProxyConfiguration {
    /// Basic authentication info.
    public var basicAuthorization: BasicAuthorization?

    /// TLS SNI value
    public var customTLSSNI: String?

    /// A bool value to determise whether proxy should skip server
    /// certificate verification.
    public var skipServerCertificateVerification: Bool = false
}

enum SOCKS5ProxyError: Error {
    case disconnected
}

/// A server-side channel handler that receives SOCKS5 requests and optionally performs a SOCKS5-upgrade.
/// Removes itself from the channel pipeline after the handshake was success, regardless of
/// whether the upgrade succeeded or not.
///
/// This handler behaves a bit differently from its Netty counterpart because it does not allow upgrade
/// on any request but the first on a connection. This is primarily to handle clients that pipeline: it's
/// sufficiently difficult to ensure that the upgrade happens at a safe time while dealing with pipelined
/// requests that we choose to punt on it entirely and not allow it. As it happens this is mostly fine:
/// the odds of someone needing to upgrade midway through the lifetime of a connection are very low.
public class SOCKS5ProxyHandler: ChannelInboundHandler {

    public enum Mode {
        case client
        case server
    }

    public typealias InboundIn = Negotiation
    public typealias OutboundOut = Negotiation

    /// Proxy configuation
    public var configuration: ProxyConfiguration
    public var mode: Mode

    private var encoder: SOCKS5Serializer
    private var decoder: SOCKS5Serializer

    private var isFinished: Bool = false

    /// The SOCKS5 Proxy Handler init
    ///
    /// - Parameters:
    ///   - configuration: <#configuration description#>
    ///   - mode: <#mode description#>
    public init(configuration: ProxyConfiguration, mode: Mode) {
        self.configuration = configuration
        self.mode = mode
        self.encoder = SOCKS5Serializer.init(kind: mode, step: .hello)
        self.decoder = SOCKS5Serializer.init(kind: mode, step: .hello)
    }

    public func handlerAdded(context: ChannelHandlerContext) {
        // Add additional encoder & decoder
        context.pipeline.addHandlers([MessageToByteHandler(encoder), ByteToMessageHandler(decoder)])
            .whenSuccess { (_) in
                // If channel active event has been fired already, which means `channelActive` will
                // not be invoked. We have to initialize here instead.
                if self.mode == .client, context.channel.isActive {
                    self.sendClientHello(context: context)
                }
        }
    }

    public func channelActive(context: ChannelHandlerContext) {
        if mode == .client {
            sendClientHello(context: context)
        }
        context.fireChannelActive()
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard !isFinished else {
            context.fireChannelRead(data)
            return
        }

        let negotiation = unwrapInboundIn(data)

        switch negotiation {
        case .hello(let response):
            decoder.step = .authentication
            receiveHelloResponse(context: context, response: response)
            encoder.step = .authentication
        case .authentication(let subnegotiation):
            decoder.step = .replies
            switch subnegotiation {
            case .basicAuth(let response):
                receiveBaisicAuthorization(context: context, response: response)
            }
            encoder.step = .replies
        case .replies(let response):
            receiveRELReply(context: context, response: response)

        case .completion(let byteBuffer):
            // TODO: pipline

            context.fireChannelRead(NIOAny(byteBuffer))
        }
    }

    /// Procedure for TCP-based clients
    /// Client send a hello greeting to server
    ///
    /// - Parameter context: The `ChannelHandlerContext` which this `ChannelHandler` belongs to.
    private func sendClientHello(context: ChannelHandlerContext) {
        var methods: [Method] = [.noAuth]
        if configuration.basicAuthorization != nil {
            methods.append(.basicAuth)
        }
        let message = HelloRequest.init(version: .v5,
                                        numberOfAuthMethods: UInt8(methods.count),
                                        methods: methods)

        context.writeAndFlush(wrapOutboundOut(.hello(message)), promise: nil)
    }


    /// Receive Server METHOD selection message
    ///
    /// - Parameters:
    ///   - context: The `ChannelHandlerContext` which this `ChannelHandler` belongs to.
    ///   - response: The METHOD selection message data struct.
    private func receiveHelloResponse(context: ChannelHandlerContext, response: Any) {

        func receiveClientHelloResponse(context: ChannelHandlerContext, response: HelloRequest) {

            var hello = HelloResponse.init(version: .v5, method: .noAcceptableMethods)

            if response.methods.contains(.noAuth) {
                hello = HelloResponse.init(version: .v5, method: .noAuth)
            } else if response.methods.contains(.basicAuth) {
                hello = HelloResponse.init(version: .v5, method: .basicAuth)
            } else {
                assertionFailure("METHOD specific negotiation not implemented.")
            }

            context.writeAndFlush(wrapOutboundOut(.hello(hello)), promise: nil)
        }

        func receiveServerHelloResponse(context: ChannelHandlerContext, response: HelloResponse) {
            switch response.method {
            case .noAuth:
                sendRELRequest(context: context)
            case .basicAuth:
                sendBasicAuthorization(context: context)
            default:
                assertionFailure("METHOD specific negotiation not implemented.")
            }
        }

        switch response {
        case let payload as HelloRequest:
            receiveClientHelloResponse(context: context, response: payload)
        case let payload as HelloResponse:
            receiveServerHelloResponse(context: context, response: payload)
        default:
            fatalError("This should never happen.")
        }
    }

    /// Client send basic authorization to server
    ///
    /// - Parameter context: The `ChannelHandlerContext` which this `ChannelHandler` belongs to.
    private func sendBasicAuthorization(context: ChannelHandlerContext) {
        guard let basicAuthorization = configuration.basicAuthorization else {
            return
        }

        let uLen = basicAuthorization.username.utf8.count
        let pLen = basicAuthorization.password.utf8.count

        let basicAuth = BasicAuthRequest.init(version: 0x01,
                                              uLength: UInt8(uLen),
                                              username: Array(basicAuthorization.username.utf8),
                                              pLength: UInt8(pLen),
                                              passwd: Array(basicAuthorization.password.utf8))

        context.writeAndFlush(wrapOutboundOut(.authentication(.basicAuth(basicAuth))), promise: nil)
    }


    /// Receive server basic authorization message
    ///
    /// - Parameters:
    ///   - context: The `ChannelHandlerContext` which this `ChannelHandler` belongs to.
    ///   - response: The basic authorization status.
    private func receiveBaisicAuthorization(context: ChannelHandlerContext, response: Any) {

        switch response {
        case let payload as BasicAuthRequest:

            let basicAuthorization = configuration.basicAuthorization
            let pwd = String.init(bytes: payload.passwd, encoding: .utf8)
            let usrname = String.init(bytes: payload.username, encoding: .utf8)

            guard pwd == basicAuthorization?.username, usrname == basicAuthorization?.username else {
                let metadata = wrapOutboundOut(.authentication(.basicAuth(BasicAuthResponse.failure)))
                context.writeAndFlush(metadata, promise: nil)
                return
            }

            let metadata = wrapOutboundOut(.authentication(.basicAuth(BasicAuthResponse.success)))
            context.writeAndFlush(metadata, promise: nil)

        case let payload as BasicAuthResponse:
            guard payload.isSuccess else {
                context.fireErrorCaught(SOCKS5ProxyError.disconnected)
                return
            }

            sendRELRequest(context: context)
        default:
            fatalError("This should never happen.")
        }
    }

    /// Client send connection request to server
    ///
    /// - Parameter context: The `ChannelHandlerContext` which this `ChannelHandler` belongs to.
    private func sendRELRequest(context: ChannelHandlerContext) {

        let ipBuffer: [UInt8] = []
        let portBuffer: [UInt8] = []

        let request = RELRequest.init(
            version: .v5,
            cmd: .connect,
            reserved: 0x00,
            addressType: .ipv4,
            desiredDestinationAddress: ipBuffer,
            desiredDestinationPort: portBuffer)

        context.writeAndFlush(wrapOutboundOut(.replies(request)), promise: nil)
    }

    /// Receive server connection response
    ///
    /// - Parameter context: The `ChannelHandlerContext` which this `ChannelHandler` belongs to.
    private func receiveRELReply(context: ChannelHandlerContext, response: Any) {

        switch response {
        case let payload as RELRequest:
            let reply = RELReply.init(version: payload.version,
                                      reply: .succeeded,
                                      reserved: payload.reserved,
                                      addressType: payload.addressType,
                                      desiredDestinationAddress: payload.desiredDestinationAddress,
                                      desiredDestinationPort: payload.desiredDestinationPort)
            context.writeAndFlush(wrapOutboundOut(.replies(reply)), promise: nil)
        case _ as RELReply:
            /// Do nothing just drop payload byte buffer.
            break
        default:
            fatalError("This should never happen.")
        }

        isFinished = true

        // TODO: Remove handler ???
    }
}
