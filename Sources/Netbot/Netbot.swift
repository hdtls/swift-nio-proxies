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
import HTTP
import Logging
import NIO
import NIOExtras
import NIOHTTP1
import NIOPosix
import SOCKS

public class Netbot {
    
    public var logger: Logger
    public var configuration: Configuration
    public var outboundMode: OutboundMode
    public var basicAuthorization: BasicAuthorization?
    public var isHTTPCaptureEnabled: Bool = false
    public var isMitmEnabled: Bool = false
    public var ruleMatcher: RuleMatcher {
        .init(rules: configuration.rules)
    }
    private var eventLoopGroup: EventLoopGroup!
    private var quiesce: ServerQuiescingHelper!
    private var threadPool: NIOThreadPool
    
    public init(logger: Logger = .init(label: "io.tenbits.Netbot"),
                configuration: Configuration,
                outboundMode: OutboundMode = .direct,
                basicAuthorization: BasicAuthorization? = nil,
                enableHTTPCapture: Bool = false,
                enableMitm: Bool = false,
                geo: GeoLite2? = nil) {
        self.logger = logger
        self.configuration = configuration
        self.outboundMode = outboundMode
        self.basicAuthorization = basicAuthorization
        self.isHTTPCaptureEnabled = enableHTTPCapture
        self.isMitmEnabled = enableMitm
        self.threadPool = .init(numberOfThreads: System.coreCount)
        
        if let geo = geo {
            GeoIPRule.geo = geo
        } else {
            var dstURL = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            dstURL.appendPathComponent("io.tenbits.Netbot")
            dstURL.appendPathComponent("GeoLite2-Country.mmdb")
            GeoIPRule.geo = try? .init(file: dstURL.path)
        }
    }
    
    public func run() throws {
        threadPool.start()
        eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
        quiesce = ServerQuiescingHelper(group: eventLoopGroup)
        
        let fullyShutdownPromise: EventLoopPromise<Void> = eventLoopGroup.next().makePromise()
        
        let signalQueue = DispatchQueue(label: "io.tenbits.Netbot.signalHandlingQueue")
        
        let signalSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: signalQueue)
        signalSource.setEventHandler {
            signalSource.cancel()
            self.logger.trace("received signal, initiating shutdown which should complete after the last request finished.")
            self.quiesce.initiateShutdown(promise: fullyShutdownPromise)
        }
        signal(SIGINT, SIG_IGN)
        signalSource.resume()
        
        if let httpListenAddress = configuration.general.httpListenAddress, let httpListenPort = configuration.general.httpListenPort {
            let bootstrap = ServerBootstrap(group: eventLoopGroup)
                .serverChannelOption(ChannelOptions.backlog, value: Int32(256))
                .serverChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: SocketOptionValue(1))
                .serverChannelInitializer { channel in
                    channel.pipeline.addHandler(self.quiesce.makeServerChannelHandler(channel: channel))
                }
                .childChannelInitializer { channel in
                    channel.pipeline.addHandlers([
                        HTTPResponseEncoder(),
                        ByteToMessageHandler(HTTPRequestDecoder(leftOverBytesStrategy: .forwardBytes)),
                        HTTP1ProxyServerHandler(authorization: self.basicAuthorization, enableHTTPCapture: self.isHTTPCaptureEnabled, enableMitM: self.isMitmEnabled, mitmConfig: self.configuration.mitm) { taskAddress in
                            
                            guard case .domainPort(let domain, _) = taskAddress else {
                                return channel.eventLoop.makeFailedFuture(SocketAddressError.unsupported)
                            }
                            
                            let eventLoop = channel.eventLoop.next()
                            
                            guard self.outboundMode != .direct, let rule = self.ruleMatcher.firstMatch(domain) else {
                                return DirectPolicy.init(taskAddress: taskAddress)
                                    .makeConnection(logger: self.logger, on: eventLoop)
                            }
                            
                            let selectablePolicyGroup = self.configuration.selectablePolicyGroups.first {
                                $0.name == rule.policy
                            }
                            
                            guard var policy = (self.configuration.policies.first {
                                $0.name == selectablePolicyGroup?.selected || $0.name == rule.policy
                            }) else {
                                // Unknown policy found.
                                return eventLoop.makeFailedFuture(ParserError.dataCorrupted)
                            }
                            
                            policy.taskAddress = taskAddress
                            return policy.makeConnection(logger: self.logger, on: eventLoop)
                        }
                    ])
                }
                .childChannelOption(ChannelOptions.socket(IPPROTO_TCP, TCP_NODELAY), value: SocketOptionValue(1))
                .childChannelOption(ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR), value: SocketOptionValue(1))
                .childChannelOption(ChannelOptions.maxMessagesPerRead, value: 1)
            
            let channel = try bootstrap
                .bind(host: httpListenAddress, port: httpListenPort)
                .wait()
            guard let localAddress = channel.localAddress else {
                fatalError("Address was unable to bind. Please check that the socket was not closed or that the address family was understood.")
            }
            
            logger.debug("HTTP proxy server started and listening on \(localAddress)")
        }
        
        try threadPool.syncShutdownGracefully()
        try fullyShutdownPromise.futureResult.wait()
        try eventLoopGroup.syncShutdownGracefully()
    }
    
    public func shutdown() {
        logger.debug("Netbot shutting down.")
        logger.trace("Shutting down eventLoopGroup \(String(describing: eventLoopGroup)).")
        do {
            let fullyShutdownPromise: EventLoopPromise<Void> = eventLoopGroup.next().makePromise()
            quiesce.initiateShutdown(promise: fullyShutdownPromise)
            
            try threadPool.syncShutdownGracefully()
            try fullyShutdownPromise.futureResult.wait()
            try eventLoopGroup.syncShutdownGracefully()
        } catch {
            logger.warning("Shutting down failed: \(error).")
        }
        
        logger.trace("Netbot shutdown complete.")
    }
    
    deinit {
        logger.trace("Netbot deinitialized, goodbye!")
    }
}
