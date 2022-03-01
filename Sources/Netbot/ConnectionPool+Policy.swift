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
import NIO
import NIOSSL
#if canImport(Network)
import NIOTransportServices
#endif

func makeUniversalBootstrap(group: EventLoopGroup, serverHostname: String) throws -> NIOClientTCPBootstrap {
#if canImport(Network)
    if #available(macOS 10.14, iOS 12, tvOS 12, watchOS 3, *) {
        // We run on a new-enough Darwin so we can use Network.framework
        let bootstrap = NIOClientTCPBootstrap(NIOTSConnectionBootstrap(group: group),
                                              tls: NIOTSClientTLSProvider())
        return bootstrap
    }
#endif
    // We are on a non-Darwin platform, so we'll use BSD sockets.
    let sslContext = try NIOSSLContext(configuration: TLSConfiguration.makeClientConfiguration())
    return try NIOClientTCPBootstrap(ClientBootstrap(group: group),
                                     tls: NIOSSLClientTLSProvider(context: sslContext,
                                                                  serverHostname: serverHostname))
}

extension DirectPolicy: ConnectionPoolSource {
    
    public func makeConnection(logger: Logger, on eventLoop: EventLoop) -> EventLoopFuture<Channel> {
        do {
            guard case .domainPort(let serverHostname, let serverPort) = taskAddress else {
                throw HTTPProxyError.invalidURL(url: String(describing: taskAddress))
            }
            return ClientBootstrap.init(group: eventLoop.next())
                .connect(host: serverHostname, port: serverPort)
        } catch {
            return eventLoop.makeFailedFuture(error)
        }
    }
}

extension RejectPolicy: ConnectionPoolSource {
    
    public func makeConnection(logger: Logger, on eventLoop: EventLoop) -> EventLoopFuture<Channel> {
        eventLoop.makeFailedFuture(ConnectionPoolError.shutdown)
    }
}

extension RejectTinyGifPolicy: ConnectionPoolSource {
    
    public func makeConnection(logger: Logger, on eventLoop: EventLoop) -> EventLoopFuture<Channel> {
        eventLoop.makeFailedFuture(ConnectionPoolError.shutdown)
    }
}

extension ShadowsocksPolicy: ConnectionPoolSource {
    
    public func makeConnection(logger: Logger, on eventLoop: EventLoop) -> EventLoopFuture<Channel> {
        do {
            guard let taskAddress = taskAddress else {
                throw HTTPProxyError.invalidURL(url: String(describing: taskAddress))
            }
            
            return ClientBootstrap.init(group: eventLoop.next())
                .channelInitializer { channel in
                    channel.pipeline.addSSClientHandlers(logger: logger, taskAddress: taskAddress, secretKey: configuration.password)
                }
                .connect(host: configuration.serverHostname, port: configuration.serverPort)
        } catch {
            return eventLoop.makeFailedFuture(error)
        }
    }
}

extension SOCKS5Policy: ConnectionPoolSource {
    
    public func makeConnection(logger: Logger, on eventLoop: EventLoop) -> EventLoopFuture<Channel> {
        do {
            guard let taskAddress = taskAddress else {
                throw HTTPProxyError.invalidURL(url: String(describing: taskAddress))
            }
            
            return ClientBootstrap.init(group: eventLoop.next())
                .channelInitializer { channel in
                    channel.pipeline.addSOCKSClientHandlers(logger: logger,
                                                            taskAddress: taskAddress,
                                                            credential: configuration.username != nil && configuration.password != nil ? .init(identity: configuration.username!, identityTokenString: configuration.password!) : nil)
                }
                .connect(host: configuration.serverHostname, port: configuration.serverPort)
        } catch {
            return eventLoop.makeFailedFuture(error)
        }
    }
}

extension SOCKS5TLSPolicy: ConnectionPoolSource {
    
    public func makeConnection(logger: Logger, on eventLoop: EventLoop) -> EventLoopFuture<Channel> {
        do {
            guard let taskAddress = taskAddress else {
                throw HTTPProxyError.invalidURL(url: String(describing: taskAddress))
            }
            
            return ClientBootstrap.init(group: eventLoop.next())
                .channelInitializer { channel in
                    channel.pipeline.addSOCKSClientHandlers(logger: logger,
                                                            taskAddress: taskAddress,
                                                            credential: configuration.username != nil && configuration.password != nil ? .init(identity: configuration.username!, identityTokenString: configuration.password!) : nil)
                }
                .connect(host: configuration.serverHostname, port: configuration.serverPort)
        } catch {
            return eventLoop.makeFailedFuture(error)
        }
    }
}

extension HTTPProxyPolicy: ConnectionPoolSource {
    
    public func makeConnection(logger: Logger, on eventLoop: EventLoop) -> EventLoopFuture<Channel> {
        eventLoop.makeFailedFuture(ConnectionPoolError.shutdown)
    }
}

extension HTTPSProxyPolicy: ConnectionPoolSource {
    
    public func makeConnection(logger: Logger, on eventLoop: EventLoop) -> EventLoopFuture<Channel> {
        eventLoop.makeFailedFuture(ConnectionPoolError.shutdown)
    }
}

extension VMESSPolicy: ConnectionPoolSource {
    
    public func makeConnection(logger: Logger, on eventLoop: EventLoop) -> EventLoopFuture<Channel> {
        do {
            guard let taskAddress = taskAddress else {
                throw HTTPProxyError.invalidURL(url: String(describing: taskAddress))
            }
            
            guard let uuidString = configuration.username, let id = UUID(uuidString: uuidString) else {
                throw EventLoopError.unsupportedOperation
            }
            
            return ClientBootstrap.init(group: eventLoop.next())
                .channelInitializer { channel in
                    channel.pipeline.addVMESSClientHandlers(logger: logger, taskAddress: taskAddress, id: id)
                }
                .connect(host: configuration.serverHostname, port: configuration.serverPort)
        } catch {
            return eventLoop.makeFailedFuture(error)
        }
    }
}
