//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright © 2019 Netbot Ltd. and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Netbot
import NIOCore
import NIOPosix

let eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)

let bootstrap = ServerBootstrap(group: eventLoopGroup)
    // Specify backlog and enable SO_REUSEADDR for the server itself
    .serverChannelOption(ChannelOptions.backlog, value: Int32(1024))
    .serverChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: SocketOptionValue(1))

    // Set handlers that are applied to the Server's channel
//    .serverChannelInitializer { channel in
//        channel.pipeline.addHandler(quiesce.makeServerChannelHandler(channel: channel))
//    }

    // Set the handlers that are applied to the accepted Channels
    .childChannelInitializer { channel in
            // add TLS handlers if configured
//        if var tlsConfiguration = configuration.tlsConfiguration {
//                // prioritize http/2
//            if configuration.supportVersions.contains(.two) {
//                tlsConfiguration.applicationProtocols.append("h2")
//            }
//            if configuration.supportVersions.contains(.one) {
//                tlsConfiguration.applicationProtocols.append("http/1.1")
//            }
//            let sslContext: NIOSSLContext
//            let tlsHandler: NIOSSLServerHandler
//            do {
//                sslContext = try NIOSSLContext(configuration: tlsConfiguration)
//                tlsHandler = NIOSSLServerHandler(context: sslContext)
//            } catch {
//                configuration.logger.error("Could not configure TLS: \(error)")
//                return channel.close(mode: .all)
//            }
//            return channel.pipeline.addHandler(tlsHandler).flatMap { _ in
//                channel.configureHTTP2SecureUpgrade(h2ChannelConfigurator: { channel in
//                    channel.configureHTTP2Pipeline(
//                        mode: .server,
//                        inboundStreamInitializer: { channel in
//                            channel.pipeline.addVaporHTTP2Handlers(
//                                application: application!,
//                                responder: responder,
//                                configuration: configuration
//                            )
//                        }
//                    ).map { _ in }
//                }, http1ChannelConfigurator: { channel in
//                    channel.pipeline.addVaporHTTP1Handlers(
//                        application: application!,
//                        responder: responder,
//                        configuration: configuration
//                    )
//                })
//            }
//        }
//        else {
//            guard !configuration.supportVersions.contains(.two) else {
//                fatalError("Plaintext HTTP/2 (h2c) not yet supported.")
//            }
//            return channel.pipeline.addVaporHTTP1Handlers(
//                application: application!,
//                responder: responder,
//                configuration: configuration
//            )
//        }
        channel.pipeline.addHandler(SOCKS5ServerProxyHandler(configuration: .init(), completion: { _ in
            channel.eventLoop.makeSucceededVoidFuture()
        }))
    }

    // Enable TCP_NODELAY and SO_REUSEADDR for the accepted Channels
    .childChannelOption(ChannelOptions.socket(IPPROTO_TCP, TCP_NODELAY), value: SocketOptionValue(1))
    .childChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: SocketOptionValue(1))
    .childChannelOption(ChannelOptions.maxMessagesPerRead, value: 1)

defer {
    try! eventLoopGroup.syncShutdownGracefully()
}

let channel = try bootstrap
    .bind(host: "127.0.0.1", port: 1234)
    .wait()

guard let localAddress = channel.localAddress else {
    fatalError("Address was unable to bind. Please check that the socket was not closed or that the address family was understood.")
}
print("Server started and listening on \(localAddress)")

    // This will never unblock as we don't close the ServerChannel.
try channel.closeFuture.wait()

print("ChatServer closed")
