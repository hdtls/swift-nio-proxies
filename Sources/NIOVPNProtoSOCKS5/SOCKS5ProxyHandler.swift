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

/// A basic username and password.
public struct BasicAuthorization: Codable, Equatable {
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
public struct ProxyConfiguration: Codable, Equatable {
    /// Basic authentication info.
    public var basicAuthorization: BasicAuthorization?

    /// TLS SNI value
    public var customTLSSNI: String?

    /// A bool value to determise whether proxy should skip server
    /// certificate verification.
    public var skipServerCertificateVerification: Bool = false

    public init(basicAuthorization: BasicAuthorization? = nil,
                customTLSSNI: String? = nil,
                skipServerCertificateVerification: Bool = false) {
        self.basicAuthorization = basicAuthorization
        self.customTLSSNI = customTLSSNI
        self.skipServerCertificateVerification = skipServerCertificateVerification
    }
}

private let SOCKS5_MAX_RECORD_SIZE = 16 * 1024

/// The base class for all SOCKS5 proxy handlers. This class cannot actually be instantiated by
/// users directly: instead, users must select which mode they would like their handler to
/// operate in, client or server.
///
/// This class exists to deal with the reality that for almost the entirety of the lifetime
/// of a SOCKS5 proxy connection.
/// For this reason almost the entirety of the implementation for the channel and server
/// handlers in SOCKS5 proxy is shared, in the form of this parent class.
public class SOCKS5ProxyHandler: ChannelInboundHandler, RFC1918 {
    public typealias InboundIn = ByteBuffer
    public typealias OutboundOut = ByteBuffer

    var method: Method = .noAuth

    enum State {
        case hello
        case authentication
        case reply
        case completion
    }

    var state: State = .hello

    private var recvBuffer: ByteBuffer

    init(channel: Channel) {
        self.recvBuffer = channel.allocator.buffer(capacity: SOCKS5_MAX_RECORD_SIZE)
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {

        var byteBuffer = unwrapInboundIn(data)
        recvBuffer.writeBuffer(&byteBuffer)

        do {
            switch state {
            case .hello:
                try recvHMsg(context: context, byteBuffer: &recvBuffer)
                state = method == .noAuth ? .reply : .authentication
            case .authentication:
                try recvAMsg(context: context, byteBuffer: &recvBuffer)
                state = .reply
            case .reply:
                try recvRELMsg(context: context, byteBuffer: &recvBuffer)
                state = .completion
            case .completion:
                context.fireChannelRead(data)
                break
            }

            // Discard readed byte to make readIndex begin with zero.
            recvBuffer.discardReadBytes()
        } catch {
            if let err = error as? SOCKS5ProxyError {
                if err == SOCKS5ProxyError.serializeFailed(reason: .needMoreBytes) {

                    // Because we have read some data in the execution of this method,
                    // when the data is insufficient, we need to re-index to ensure the
                    // data integrity of the next execution of the method.
                    recvBuffer.moveReaderIndex(to: 0)
                    return
                }
            }
            context.fireErrorCaught(error)
        }
    }

    public func recvHMsg(context: ChannelHandlerContext, byteBuffer: inout ByteBuffer) throws {
        fatalError("this must be overridden by sub class")
    }

    public func writeHMsg(context: ChannelHandlerContext) {
        fatalError("this must be overridden by sub class")
    }

    public func recvAMsg(context: ChannelHandlerContext, byteBuffer: inout ByteBuffer) throws {
        fatalError("this must be overridden by sub class")
    }

    public func writeAMsg(context: ChannelHandlerContext) {
        fatalError("this must be overridden by sub class")
    }

    public func recvRELMsg(context: ChannelHandlerContext, byteBuffer: inout ByteBuffer) throws {
        fatalError("this must be overridden by sub class")
    }

    public func writeRELMsg(context: ChannelHandlerContext) {
        fatalError("this must be overridden by sub class")
    }
}
