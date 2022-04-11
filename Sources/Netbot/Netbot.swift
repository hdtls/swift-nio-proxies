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
@_exported import Logging
@_exported import MaxMindDB
@_exported import NetbotCore
@_exported import NetbotHTTP
@_exported import NetbotSOCKS
@_exported import NetbotSS
@_exported import NetbotTrojan
@_exported import NetbotVMESS
@_exported import NIOCore
@_exported import NIOExtras
@_exported import NIOHTTP1
@_exported import NIOPosix
@_exported import ConnectionPool

public class Netbot {
    
    public let logger: Logger
    
    public var configuration: Configuration
    
    public var outboundMode: OutboundMode
    
    public var isHTTPCaptureEnabled: Bool = false
    
    public var isMitmEnabled: Bool = false
    
    public var geoLite2: MaxMindDB {
        set { GeoIPRule.geo = newValue }
        get { GeoIPRule.geo! }
    }
    
    private var eventLoopGroup: EventLoopGroup!
    
    private var quiesce: ServerQuiescingHelper!
    
    public lazy var threadPool: NIOThreadPool = {
        NIOThreadPool.init(numberOfThreads: System.coreCount)
    }()
    
    private var cache: LRUCache<String, AnyRule> = .init(capacity: 100)
    
    public init(configuration: Configuration,
                outboundMode: OutboundMode = .direct,
                enableHTTPCapture: Bool = false,
                enableMitm: Bool = false,
                geoLite2: MaxMindDB) {
        
        LoggingSystem.bootstrap { label in
            var handler = StreamLogHandler.standardOutput(label: label)
            handler.logLevel = configuration.general.logLevel
            return handler
        }
        
        self.logger = .init(label: "io.tenbits.Netbot")
        self.configuration = configuration
        self.outboundMode = outboundMode
        self.isHTTPCaptureEnabled = enableHTTPCapture
        self.isMitmEnabled = enableMitm
        self.geoLite2 = geoLite2
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
                    channel.pipeline.configureHTTPProxyServerPipeline(
                        logger: self.logger,
                        enableHTTPCapture: self.isHTTPCaptureEnabled,
                        enableMitM: self.isMitmEnabled,
                        mitmConfig: self.configuration.mitm) { req in
                            let eventLoop = channel.eventLoop.next()
                            
                            let taskAddress: NetAddress
                            do {
                                taskAddress = try req.address
                            } catch {
                                return eventLoop.makeFailedFuture(error)
                            }
                            
                            guard self.outboundMode != .direct else {
                                return DirectPolicy(taskAddress: taskAddress)
                                    .makeConnection(logger: self.logger, on: eventLoop)
                            }
                            
                            // DNS lookup for taskAddress.
                            // This results will be used for rule matching.
                            let dnsLookupPromise = eventLoop.makePromise(of: [NetAddress].self)
                            
                            let dnsLookupStartTimeInterval = DispatchTime.now().uptimeNanoseconds
                            
                            switch taskAddress {
                                case .domainPort(let domain, let port):
                                    let resolver = GetaddrinfoResolver(eventLoop: eventLoop)
                                    let dnsLookup = EventLoopFuture.whenAllSucceed([
                                        resolver.initiateAQuery(host: domain, port: port)
                                            .flatMapErrorThrowing { _ in Array<SocketAddress>() },
                                        resolver.initiateAAAAQuery(host: domain, port: port)
                                            .flatMapErrorThrowing { _ in Array<SocketAddress>() }
                                    ], on: eventLoop)
                                    
                                    dnsLookup
                                        .map {
                                            $0.joined().map {
                                                NetAddress.socketAddress($0)
                                            } + [taskAddress]
                                        }
                                        .cascade(to: dnsLookupPromise)
                                case .socketAddress:
                                    dnsLookupPromise.succeed([taskAddress])
                            }
                            
                            return dnsLookupPromise.futureResult
                                .map { addresses -> [String] in
                                    self.logger.info("DNS Lookup end with \((DispatchTime.now().uptimeNanoseconds - dnsLookupStartTimeInterval) / 1000)ms.", metadata: ["Request" : "\(taskAddress)"])
                                    return addresses.map {
                                        // Map domainPort address to domain
                                        // and socketAddress to pathname if is unixDomainSocket else ipAddress.
                                        switch $0 {
                                            case .domainPort(let domain, _):
                                                return domain
                                            case .socketAddress(let addrinfo):
                                                return addrinfo.ipAddress ?? addrinfo.pathname!
                                        }
                                    }
                                }
                                .map { patterns -> AnyRule in
                                    // Rule evaluating.
                                    var savedFinalRule: AnyRule?
                                    
                                    let startTime = DispatchTime.now().uptimeNanoseconds
                                    
                                    defer {
                                        self.logger.info("Rule evaluating - \(savedFinalRule!)", metadata: ["Request" : "\(taskAddress)"])
                                        self.logger.info("Rule evaluating end with \((DispatchTime.now().uptimeNanoseconds - startTime) / 1000)ms.", metadata: ["Request" : "\(taskAddress)"])
                                    }
                                    
                                    // Fetch rule from LRU cache.
                                    for pattern in patterns {
                                        savedFinalRule = self.cache[pattern]
                                        if savedFinalRule != nil {
                                            return savedFinalRule!
                                        }
                                    }
                                    
                                    for rule in self.configuration.rules {
                                        guard patterns.first(where: rule.match) == nil else {
                                            savedFinalRule = rule
                                            break
                                        }
                                        
                                        if rule.base is FinalRule {
                                            savedFinalRule = rule
                                        }
                                    }
                                    
                                    // Cache rule evaluating result.
                                    patterns.forEach { pattern in
                                        self.cache[pattern] = savedFinalRule
                                    }
                                    precondition(savedFinalRule != nil, "Rules defined in configuration MUST contain one and only one FinalRule.")
                                    return savedFinalRule!
                                }
                                .map { rule -> ProxyPolicy in
                                    // Policy evaluating.
                                    let fallback = ProxyPolicy.direct(.init())
                                    
                                    var preferred: String?
                                    
                                    // Check whether there is a `SelectablePolicyGroup`
                                    // with then same name as the rule's policy in
                                    // `policyGroups`, if group exists use group's
                                    // `selected` as policy ID else use rule's policy as ID.
                                    if let policyGroup = (self.configuration.policyGroups.first { $0.name == rule.policy }) {
                                        preferred = policyGroup.policies.first
                                    } else {
                                        preferred = rule.policy
                                    }
                                    
                                    // The user may not have preferred policy, so if not
                                    // we should fallback.
                                    guard let preferred = preferred else {
                                        return fallback
                                    }
                                    
                                    let policy = (self.configuration.policies + Builtin.policies).first {
                                        $0.name == preferred
                                    }
                                    
                                    assert(policy != nil, "Illegal selectable policy groups, all policies group should be one of the policies in same configuration.")
                                    return policy!
                                }
                                .flatMap {
                                    self.logger.info("Policy evaluating - \($0.name)", metadata: ["Request" : "\(taskAddress)"])
                                    var policy = $0
                                    policy.taskAddress = taskAddress
                                    return policy.makeConnection(logger: self.logger, on: eventLoop)
                                }
                        }
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
