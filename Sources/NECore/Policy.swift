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

/// Source of new connections for `ConnectionPool`.
public protocol ConnectionPoolSource {

  /// Creates a new connection.
  func makeConnection(logger: Logger, on eventLoop: EventLoop) -> EventLoopFuture<Channel>
}

/// Policy protocol representation a policy object.
public protocol Policy: ConnectionPoolSource, Sendable {

  /// The name of the policy.
  var name: String { get set }

  /// Destination address.
  var destinationAddress: NetAddress? { get set }
}

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

/// DirectPolicy will tunnel connection derectly.
public struct DirectPolicy: Policy {

  public var name: String = "DIRECT"

  public var destinationAddress: NetAddress?

  public init(name: String, destinationAddress: NetAddress? = nil) {
    self.name = name
    self.destinationAddress = destinationAddress
  }

  public init(destinationAddress: NetAddress) {
    self.destinationAddress = destinationAddress
  }

  public init() {}

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

struct RejectByRuleError: Error {}

/// RejectPolicy will reject connection to the destination.
public struct RejectPolicy: Policy {

  public var name: String = "REJECT"

  public var destinationAddress: NetAddress?

  public init(name: String, destinationAddress: NetAddress? = nil) {
    self.name = name
    self.destinationAddress = destinationAddress
  }

  public init(destinationAddress: NetAddress) {
    self.destinationAddress = destinationAddress
  }

  public init() {}

  public func makeConnection(logger: Logger, on eventLoop: EventLoop) -> EventLoopFuture<Channel> {
    eventLoop.makeFailedFuture(RejectByRuleError())
  }
}

/// RejectTinyGifPolicy will reject connection and response a tiny gif.
public struct RejectTinyGifPolicy: Policy {

  public var name: String = "REJECT-TINYGIF"

  public var destinationAddress: NetAddress?

  public init(name: String, destinationAddress: NetAddress? = nil) {
    self.name = name
    self.destinationAddress = destinationAddress
  }

  public init(destinationAddress: NetAddress) {
    self.destinationAddress = destinationAddress
  }

  public init() {}

  public func makeConnection(logger: Logger, on eventLoop: EventLoop) -> EventLoopFuture<Channel> {
    eventLoop.makeFailedFuture(RejectByRuleError())
  }
}

public struct ProxyPolicy: Policy {

  public var name: String

  public var proxy: Proxy

  public var destinationAddress: NetAddress?

  public init(name: String, proxy: Proxy, destinationAddress: NetAddress) {
    self.name = name
    self.proxy = proxy
    self.destinationAddress = destinationAddress
  }

  public init(name: String, proxy: Proxy) {
    self.name = name
    self.proxy = proxy
  }

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
