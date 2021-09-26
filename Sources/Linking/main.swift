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

import Foundation
import Netbot

let serverIpAddress = "192.168.0.101"

let socks5ListenAddress = "127.0.0.1"
let socks5ListenPort = "6153"
let httpListenAddress = socks5ListenAddress
let httpListenPort = "6152"

//ProxiesControlCommand.main([
//    "install",
//    "--socks5-listen-address", socks5ListenAddress,
//    "--socks5-listen-port", socks5ListenPort,
//    "--http-listen-address", httpListenAddress,
//    "--http-listen-port", httpListenPort,
//    "--exclude-simple-hostnames",
//    "--exceptions", "localhost,*.local,localhost,*.apple.com,0.0.0.0/8,10.0.0.0/8,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.0.0.0/24,192.0.2.0/24,192.168.0.0/16,192.88.99.0/24,198.18.0.0/15,198.51.100.0/24,203.0.113.0/24,224.0.0.0/4,240.0.0.0/4,255.255.255.255/32"
//])

//BoringSSLCommand.main(["install"])

LoggingSystem.bootstrap { label in
    var handler = StreamLogHandler.standardOutput(label: label)
    handler.logLevel = .debug
    return handler
}

let baseAddress = try SocketAddress(ipAddress: serverIpAddress, port: 8389)
//let baseAddress = try SocketAddress(ipAddress: serverIpAddress, port: 8385)

let credential = SOCKS.Credential(identity: "Netbot", identityTokenString: "com.netbot.credential")

let eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
defer {
    try! eventLoopGroup.syncShutdownGracefully()
}

public enum OutboundMode {
    case direct
    case globalProxy
    case ruleBasedProxy
}

let outboundMode = OutboundMode.direct

let bootstrap = ServerBootstrap(group: eventLoopGroup)
    .serverChannelOption(ChannelOptions.backlog, value: Int32(1024))
    .serverChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: SocketOptionValue(1))
    .childChannelInitializer { channel in
        channel.pipeline.addHandlers([
            HTTPResponseEncoder(),
            ByteToMessageHandler(HTTPRequestDecoder(leftOverBytesStrategy: .forwardBytes)),
            HTTP1ProxyServerHandler { taskAddress in
                let bootstrap = ClientBootstrap(group: channel.eventLoop.next())
                    .channelInitializer { client in
                                                client.pipeline.eventLoop.makeSucceededVoidFuture()
//                        client.pipeline.addSSClientHandlers(taskAddress: taskAddress, secretKey: credential.identityTokenString)
                        //                        client.pipeline.addSOCKSClientHandlers(taskAddress: taskAddress, credential: credential)
                    }
                
                if outboundMode == .direct {
                    switch taskAddress {
                        case .domainPort(let domain, let port):
                            return bootstrap.connect(host: domain, port: port)
                        case .socketAddress(let socketAddress):
                            return bootstrap.connect(to: socketAddress)
                    }
                } else {
                    return bootstrap.connect(host: serverIpAddress, port: 8389)
                }
            }
        ])
    }
    .childChannelOption(ChannelOptions.socket(IPPROTO_TCP, TCP_NODELAY), value: SocketOptionValue(1))
    .childChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: SocketOptionValue(1))
    .childChannelOption(ChannelOptions.maxMessagesPerRead, value: 1)

let channel = try bootstrap
    .bind(host: httpListenAddress, port: Int(httpListenPort)!)
    .wait()

guard let localAddress = channel.localAddress else {
    fatalError("Address was unable to bind. Please check that the socket was not closed or that the address family was understood.")
}

print("Server started and listening on \(localAddress)")

try channel.closeFuture.wait()
