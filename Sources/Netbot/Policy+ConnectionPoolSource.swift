//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2021 Junfeng Zhang. and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import ConnectionPool
import Foundation
import Logging
import NIOCore
import NIOPosix
import NIOSSL
import NetbotHTTP
import NetbotSS
import NetbotSOCKS
import NetbotVMESS

#if canImport(Network)
import NIOTransportServices
#endif

func makeClientTCPBootstrap(group: EventLoopGroup, serverHostname: String? = nil) throws
    -> NIOClientTCPBootstrap
{
    #if canImport(Network)
    if #available(macOS 10.14, iOS 12, tvOS 12, watchOS 3, *) {
        // We run on a new-enough Darwin so we can use Network.framework
        let bootstrap = NIOClientTCPBootstrap(
            NIOTSConnectionBootstrap(group: group),
            tls: NIOTSClientTLSProvider()
        )
        return bootstrap
    }
    #endif
    // We are on a non-Darwin platform, so we'll use BSD sockets.
    let sslContext = try NIOSSLContext(configuration: TLSConfiguration.makeClientConfiguration())
    return try NIOClientTCPBootstrap(
        ClientBootstrap(group: group),
        tls: NIOSSLClientTLSProvider(
            context: sslContext,
            serverHostname: serverHostname
        )
    )
}

extension DirectPolicy: ConnectionPoolSource {

    public func makeConnection(logger: Logger, on eventLoop: EventLoop) -> EventLoopFuture<Channel>
    {
        do {
            guard case .domainPort(let serverHostname, let serverPort) = destinationAddress else {
                throw HTTPProxyError.invalidURL(url: String(describing: destinationAddress))
            }
            return ClientBootstrap.init(group: eventLoop.next())
                .connect(host: serverHostname, port: serverPort)
        } catch {
            return eventLoop.makeFailedFuture(error)
        }
    }
}

extension RejectPolicy: ConnectionPoolSource {

    public func makeConnection(logger: Logger, on eventLoop: EventLoop) -> EventLoopFuture<Channel>
    {
        eventLoop.makeFailedFuture(ConnectionPoolError.shutdown)
    }
}

extension RejectTinyGifPolicy: ConnectionPoolSource {

    public func makeConnection(logger: Logger, on eventLoop: EventLoop) -> EventLoopFuture<Channel>
    {
        eventLoop.makeFailedFuture(ConnectionPoolError.shutdown)
    }
}

extension ProxyPolicy: ConnectionPoolSource {

    public func makeConnection(logger: Logger, on eventLoop: EventLoop) -> EventLoopFuture<Channel>
    {
        do {
            precondition(destinationAddress != nil)
            let destinationAddress = destinationAddress!

            var bootstrap = try makeClientTCPBootstrap(group: eventLoop.next())

            if proxy.overTls {
                bootstrap = bootstrap.enableTLS()
            }

            switch proxy.protocol {
                case .http:
                    return bootstrap.channelInitializer { channel in
                        channel.pipeline.addHTTPProxyClientHandlers(
                            logger: logger,
                            username: proxy.username,
                            passwordReference: proxy.passwordReference,
                            authenticationRequired: proxy.authenticationRequired,
                            preferHTTPTunneling: proxy.prefererHttpTunneling,
                            destinationAddress: destinationAddress
                        )
                    }
                    .connect(host: proxy.serverAddress, port: proxy.port)
                case .socks5:
                    return bootstrap.channelInitializer { channel in
                        channel.pipeline.addSOCKSClientHandlers(
                            logger: logger,
                            username: proxy.username,
                            passwordReference: proxy.passwordReference,
                            authenticationRequired: proxy.authenticationRequired,
                            destinationAddress: destinationAddress
                        )
                    }
                    .connect(host: proxy.serverAddress, port: proxy.port)
                case .shadowsocks:
                    return bootstrap.channelInitializer { channel in
                        channel.pipeline.addSSClientHandlers(
                            logger: logger,
                            algorithm: proxy.algorithm,
                            passwordReference: proxy.passwordReference,
                            taskAddress: destinationAddress
                        )
                    }
                    .connect(host: proxy.serverAddress, port: proxy.port)
                case .vmess:
                    return bootstrap.channelInitializer { channel in
                        channel.pipeline.addVMESSClientHandlers(
                            logger: logger,
                            username: UUID(uuidString: proxy.username)!,
                            destinationAddress: destinationAddress
                        )
                    }
                    .connect(host: proxy.serverAddress, port: proxy.port)
            }
        } catch {
            return eventLoop.makeFailedFuture(error)
        }
    }
}
