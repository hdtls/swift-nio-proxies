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
import SOCKS
import NIOExtras

public class Netbot {
    
    public var logger: Logger
    public var configuration: Configuration
    public var outboundMode: OutboundMode
    public var basicAuthorization: BasicAuthorization?
    public var isHTTPCaptureEnabled: Bool = false
    public var isMitmEnabled: Bool = false
    public private(set) var isRunning: Bool
    
    private var eventLoopGroup: EventLoopGroup!
    private var quiesce: ServerQuiescingHelper!
    
    public init(logger: Logger = .init(label: "com.netbot.logging"),
                configuration: Configuration,
                outboundMode: OutboundMode = .direct,
                basicAuthorization: BasicAuthorization? = nil,
                enableHTTPCapture: Bool = false,
                enableMitm: Bool = false) {
        self.logger = logger
        self.configuration = configuration
        self.outboundMode = outboundMode
        self.basicAuthorization = basicAuthorization
        self.isHTTPCaptureEnabled = enableHTTPCapture
        self.isMitmEnabled = enableMitm
        self.isRunning = false
    }
    
    public func run() throws {
        precondition(!isRunning, "Netbot has already started.")
        
        eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
        quiesce = ServerQuiescingHelper(group: eventLoopGroup)
        
        let fullyShutdownPromise: EventLoopPromise<Void> = eventLoopGroup.next().makePromise()
        
        let signalQueue = DispatchQueue(label: "io.netbot.signalHandlingQueue")
        
        let signalSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: signalQueue)
        signalSource.setEventHandler {
            signalSource.cancel()
            self.logger.trace("received signal, initiating shutdown which should complete after the last request finished.")
            self.quiesce.initiateShutdown(promise: fullyShutdownPromise)
        }
        signal(SIGINT, SIG_IGN)
        signalSource.resume()
        
        if let httpListenAddress = configuration.generalField.httpListenAddress, let httpListenPort = configuration.generalField.httpListenPort {
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
                        HTTP1ProxyServerHandler(authorization: self.basicAuthorization, enableHTTPCapture: self.isHTTPCaptureEnabled, enableMitM: self.isMitmEnabled, mitmConfig: self.configuration.mitmField) { taskAddress in
                            
                            let profile: HTTPProxyProfile = .init(name: "DIRECT", protocol: .direct, user: "", token: "", address: "", port: 0)
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
            
            do {
                let channel = try bootstrap
                    .bind(host: httpListenAddress, port: httpListenPort)
                    .wait()
                guard let localAddress = channel.localAddress else {
                    fatalError("Address was unable to bind. Please check that the socket was not closed or that the address family was understood.")
                }
                
                logger.debug("HTTP proxy server started and listening on \(localAddress)")
            } catch {
                try eventLoopGroup.syncShutdownGracefully()
                throw error
            }
        }
        
        isRunning = true
        
        try fullyShutdownPromise.futureResult.wait()
        try eventLoopGroup.syncShutdownGracefully()
    }
    
    public func shutdown() {
        precondition(isRunning, "Netbot has already shut down.")
        logger.debug("Netbot shutting down.")
        logger.trace("Shutting down eventLoopGroup \(String(describing: eventLoopGroup)).")
        do {
            let fullyShutdownPromise: EventLoopPromise<Void> = eventLoopGroup.next().makePromise()
            quiesce.initiateShutdown(promise: fullyShutdownPromise)
            
            try fullyShutdownPromise.futureResult.wait()
            try eventLoopGroup.syncShutdownGracefully()
        } catch {
            logger.warning("Shutting down failed: \(error).")
        }
        
        isRunning = false
        logger.trace("Netbot shutdown complete.")
    }
    
    deinit {
        logger.trace("Netbot deinitialized, goodbye!")
        if isRunning {
            assertionFailure("\(self).shutdown() was not called before deinitialized.")
        }
    }
}
