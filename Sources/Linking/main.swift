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

import Netbot
import Crypto

LoggingSystem.bootstrap { label in
    var handler = StreamLogHandler.standardOutput(label: label)
    handler.logLevel = .debug
    return handler
}

extension String {
    func asSocketAddress() throws -> SocketAddress {
        let splitted = split(separator: ":")
        let host = String(splitted.first!)
        let port = Int(splitted.last!) ?? 80
        return try SocketAddress.makeAddressResolvingHost(host, port: port)
    }
}

//let baseAddress = try "127.0.0.1:8389".asSocketAddress()
let baseAddress = try "127.0.0.1:8385".asSocketAddress()
let credential = SOCKS.Credential(identity: "Netbot", identityTokenString: "com.netbot.credential")

let eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)

let bootstrap = ServerBootstrap(group: eventLoopGroup)
    .serverChannelOption(ChannelOptions.backlog, value: Int32(1024))
    .serverChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: SocketOptionValue(1))
    .childChannelInitializer { channel in
        return channel.pipeline.addHandlers([
            HTTPResponseEncoder(),
            ByteToMessageHandler(HTTPRequestDecoder(leftOverBytesStrategy: .forwardBytes)),
            RuleFilterHandler(),
            HTTP1ServerCONNECTTunnelHandler { result in
                ClientBootstrap(group: channel.eventLoop.next())
                    .channelInitializer { client in
                        client.pipeline.addHandlers([
                            SOCKSClientHandler(credential: socksCredential, targetAddress: .address(try! result.asSocketAddress())),
                        ])
                    }
                    .connect(to: baseAddress)
            }
        ])
    }
    .childChannelOption(ChannelOptions.socket(IPPROTO_TCP, TCP_NODELAY), value: SocketOptionValue(1))
    .childChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: SocketOptionValue(1))
    .childChannelOption(ChannelOptions.maxMessagesPerRead, value: 1)

defer {
    try! eventLoopGroup.syncShutdownGracefully()
}

let channel = try bootstrap
    .bind(host: "127.0.0.1", port: 6152)
    .wait()

guard let localAddress = channel.localAddress else {
    fatalError("Address was unable to bind. Please check that the socket was not closed or that the address family was understood.")
}

print("Server started and listening on \(localAddress)")

try channel.closeFuture.wait()
