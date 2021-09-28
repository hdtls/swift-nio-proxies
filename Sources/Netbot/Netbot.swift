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

import ArgumentParser
import Foundation
import HTTP
import Logging
import NIO
import SOCKS

public class Netbot {
    
    public var logger: Logger
    public var outboundMode: OutboundMode
    public let httpListenAddress: String?
    public let httpListenPort: Int?
    public let socksListenAddress: String?
    public let socksListenPort: Int?
    public var reqMsgFilters: [String]?
    public var rules: [Rule] = []
    public var mitmHostnames: [String]?
    public private(set) var didShutdown: Bool
    
    private let eventLoopGroup: EventLoopGroup
    private var httpChannel: Channel?
    private var socksChannel: Channel?
    
    public init(logger: Logger = .init(label: "com.netbot.logging"),
                outboundMode: OutboundMode = .direct,
                httpListenAddress: String?,
                httpListenPort: Int?,
                socksListenAddress: String?,
                socksListenPort: Int?,
                reqMsgFilters: [String]?,
                mitmHostnames: [String]?) {
        self.eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
        self.logger = logger
        self.outboundMode = outboundMode
        self.httpListenAddress = httpListenAddress
        self.httpListenPort = httpListenPort
        self.socksListenAddress = socksListenAddress
        self.socksListenPort = socksListenPort
        self.reqMsgFilters = reqMsgFilters
        self.mitmHostnames = mitmHostnames
        self.didShutdown = false
    }
    
    public func run() throws {
        if let httpListenAddress = httpListenAddress, let httpListenPort = httpListenPort {
            let bootstrap = ServerBootstrap(group: eventLoopGroup)
                .serverChannelOption(ChannelOptions.backlog, value: Int32(1024))
                .serverChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: SocketOptionValue(1))
                .childChannelInitializer { channel in
                    channel.pipeline.addHandlers([
                        HTTPResponseEncoder(),
                        ByteToMessageHandler(HTTPRequestDecoder(leftOverBytesStrategy: .forwardBytes)),
                        HTTP1ProxyServerHandler { taskAddress in
                            
                            let profile: ProxyProfile = .init(name: "DIRECT", protocol: .direct, user: "", token: "", address: "", port: 0)
                            let bootstrap = ClientBootstrap(group: channel.eventLoop.next())
                            
                            guard self.outboundMode != .direct, profile.protocol != .direct else {
                                switch taskAddress {
                                    case .domainPort(let domain, let port):
                                        return bootstrap.connect(host: domain, port: port)
                                    case .socketAddress(let socketAddress):
                                        return bootstrap.connect(to: socketAddress)
                                }
                            }
                            
                            return bootstrap
                                .channelInitializer { channel in
                                    channel.eventLoop.makeSucceededVoidFuture()
                                    //                        profile.initialize(on: channel, taskAddress: taskAddress)
                                }
                                .connect(host: profile.address, port: profile.port)
                        }
                    ])
                }
                .childChannelOption(ChannelOptions.socket(IPPROTO_TCP, TCP_NODELAY), value: SocketOptionValue(1))
                .childChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: SocketOptionValue(1))
                .childChannelOption(ChannelOptions.maxMessagesPerRead, value: 1)
            
            httpChannel = try bootstrap
                .bind(host: httpListenAddress, port: httpListenPort)
                .wait()
            
            guard let localAddress = httpChannel!.localAddress else {
                fatalError("Address was unable to bind. Please check that the socket was not closed or that the address family was understood.")
            }
            
            logger.info("HTTP proxy server started and listening on \(localAddress)")
        }
        
        try httpChannel?.closeFuture.wait()
    }
    
    public func shutdown() {
        assert(!didShutdown, "Netbot has already shut down.")
        logger.debug("Netbot shutting down.")
        logger.trace("Shutting down eventLoopGroup \(eventLoopGroup).")
        do {
            try eventLoopGroup.syncShutdownGracefully()
        } catch {
            logger.warning("Shutting down eventLoopGroup failed: \(error).")
        }
        
        didShutdown = true
        logger.trace("Netbot shutdown complete.")
    }
    
    deinit {
        logger.trace("Netbot deinitialized, goodbye!")
        if !didShutdown {
            assertionFailure("\(self).shutdown() was not called before deinitialized.")
        }
    }
}
