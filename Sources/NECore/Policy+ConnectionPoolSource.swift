//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2021 Junfeng Zhang and the Netbot project authors
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
@_exported import NEConnectionPool
import NEHTTP
import NESOCKS
import NESS
import NEVMESS
@_exported import NIOCore
import NIOPosix
import NIOSSL

#if canImport(Network) && ENABLE_NIO_TRANSPORT_SERVICES
import Network
import NIOTransportServices
#endif

func makeUniversalClientTCPBootstrap(group: EventLoopGroup, serverHostname: String? = nil) throws
  -> NIOClientTCPBootstrap
{
  #if canImport(Network) && ENABLE_NIO_TRANSPORT_SERVICES
  // We run on a new-enough Darwin so we can use Network.framework
  let bootstrap = NIOClientTCPBootstrap(
    NIOTSConnectionBootstrap(group: group),
    tls: NIOTSClientTLSProvider()
  )
  return bootstrap
  #else
  // We are on a non-Darwin platform, so we'll use BSD sockets.
  let sslContext = try NIOSSLContext(configuration: TLSConfiguration.makeClientConfiguration())
  return try NIOClientTCPBootstrap(
    ClientBootstrap(group: group),
    tls: NIOSSLClientTLSProvider(
      context: sslContext,
      serverHostname: serverHostname
    )
  )
  #endif
}

extension DirectPolicy: ConnectionPoolSource {

  public func makeConnection(logger: Logger, on eventLoop: EventLoop) -> EventLoopFuture<Channel> {
    do {
      guard case .domainPort(let serverHostname, let serverPort) = destinationAddress else {
        throw SocketAddressError.unsupported
      }
      let bootstrap = try makeUniversalClientTCPBootstrap(group: eventLoop)

      #if canImport(Network) && ENABLE_NIO_TRANSPORT_SERVICES
      if let bootstrap = bootstrap.underlyingBootstrap as? NIOTSConnectionBootstrap {
        let parameters = NWParameters.tcp
        parameters.preferNoProxies = true
        let host: NWEndpoint.Host = .init(serverHostname)
        let port: NWEndpoint.Port = .init(rawValue: UInt16(serverPort))!
        return bootstrap.withExistingNWConnection(.init(host: host, port: port, using: parameters))
      } else {
        return bootstrap.connect(host: serverHostname, port: serverPort)
      }
      #else
      return bootstrap.connect(host: serverHostname, port: serverPort)
      #endif
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

extension ProxyPolicy: ConnectionPoolSource {

  public func makeConnection(logger: Logger, on eventLoop: EventLoop) -> EventLoopFuture<Channel> {
    do {
      guard let destinationAddress else {
        fatalError()
      }

      var bootstrap = try makeUniversalClientTCPBootstrap(group: eventLoop)

      if proxy.overTls {
        bootstrap = bootstrap.enableTLS()
      }

      switch proxy.protocol {
      case .http:
        bootstrap = bootstrap.channelInitializer { channel in
          channel.pipeline.addHTTPProxyClientHandlers(
            username: proxy.username,
            passwordReference: proxy.passwordReference,
            authenticationRequired: proxy.authenticationRequired,
            preferHTTPTunneling: proxy.prefererHttpTunneling,
            destinationAddress: destinationAddress
          )
        }
      case .socks5:
        bootstrap = bootstrap.channelInitializer { channel in
          channel.pipeline.addSOCKSClientHandlers(
            username: proxy.username,
            passwordReference: proxy.passwordReference,
            authenticationRequired: proxy.authenticationRequired,
            destinationAddress: destinationAddress
          )
        }
      case .shadowsocks:
        bootstrap = bootstrap.channelInitializer { channel in
          channel.pipeline.addSSClientHandlers(
            algorithm: proxy.algorithm,
            passwordReference: proxy.passwordReference,
            destinationAddress: destinationAddress
          )
        }
      case .vmess:
        bootstrap = bootstrap.channelInitializer { channel in
          channel.pipeline.addVMESSClientHandlers(
            username: UUID(uuidString: proxy.username) ?? UUID(),
            destinationAddress: destinationAddress
          )
        }
      }

      #if canImport(Network) && ENABLE_NIO_TRANSPORT_SERVICES
      if let bootstrap = bootstrap.underlyingBootstrap as? NIOTSConnectionBootstrap {
        let parameters = NWParameters.tcp
        parameters.preferNoProxies = true
        let host: NWEndpoint.Host = .init(proxy.serverAddress)
        let port: NWEndpoint.Port = .init(rawValue: UInt16(proxy.port))!
        return bootstrap.withExistingNWConnection(.init(host: host, port: port, using: parameters))
      } else {
        return bootstrap.connect(host: proxy.serverAddress, port: proxy.port)
      }
      #else
      return bootstrap.connect(host: proxy.serverAddress, port: proxy.port)
      #endif
    } catch {
      return eventLoop.makeFailedFuture(error)
    }
  }
}
