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

let logger = Logger.init(label: "com.netbot.client-logging")

class LogHandler: ChannelInboundHandler {
    typealias InboundIn = NIOAny
    
    func errorCaught(context: ChannelHandlerContext, error: Error) {
        logger.error("\(error)")
    }
}


extension String {
    func asSocketAddress() throws -> SocketAddress {
        let splitted = split(separator: ":")
        let host = String(splitted.first!)
        let port = Int(splitted.last!) ?? 80
        return try SocketAddress.makeAddressResolvingHost(host, port: port)
    }
}

let baseAddress = try SocketAddress(ipAddress: "172.105.214.180", port: 8385)
let socksCredential = SOCKSClientHandler.Credential(user: "Netbot", password: "netbot.akii.me")

let eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)

let bootstrap = ServerBootstrap(group: eventLoopGroup)
    .serverChannelOption(ChannelOptions.backlog, value: Int32(1024))
    .serverChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: SocketOptionValue(1))
    .childChannelInitializer { channel in
        return channel.pipeline.addHandler(HTTPServerProxyHandler { result in
            return ClientBootstrap(group: channel.eventLoop.next())
                .channelInitializer { peerChannel in
                    peerChannel.pipeline.addHandlers([
                        SOCKSClientHandler(credential: socksCredential, targetAddress: .address(try! result.get().uri.asSocketAddress())),
                        LogHandler()
                    ])
                }
                .connect(to: baseAddress)
        })
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
