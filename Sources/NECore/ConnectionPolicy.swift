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
import Logging
import NEHTTP
import NESOCKS
import NESS
import NEVMESS
import NIOCore
import NIOPosix
import NIOSSL
import NIOWebSocket

#if canImport(Network) && ENABLE_NIO_TRANSPORT_SERVICES
import Network
import NIOTransportServices
#endif

/// Source of new connections for `ConnectionPool`.
public protocol ConnectionPoolSource {

  /// Creates a new connection.
  func makeConnection(logger: Logger, on eventLoop: EventLoop) -> EventLoopFuture<Channel>
}

/// ConnectionPolicy protocol representation a policy object.
public protocol ConnectionPolicy: ConnectionPoolSource, Sendable {

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
public struct DirectPolicy: ConnectionPolicy {

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
public struct RejectPolicy: ConnectionPolicy {

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
public struct RejectTinyGifPolicy: ConnectionPolicy {

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

public struct ProxyPolicy: ConnectionPolicy {

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

      var bootstrap =
        try makeUniversalClientTCPBootstrap(group: eventLoop, serverHostname: proxy.serverAddress)
        .channelInitializer { channel in
          guard proxy.overWebSocket else {
            return channel.pipeline.addClientHandlers(
              proxy: proxy,
              destinationAddress: destinationAddress
            )
          }

          let requestWriter = HTTPRequestWriter(
            host: proxy.serverAddress,
            port: proxy.port,
            uri: proxy.webSocketPath
          )
          let requestEncoder = HTTPRequestEncoder()
          let responseDecoder = HTTPResponseDecoder(leftOverBytesStrategy: .dropBytes)
          var handlers: [RemovableChannelHandler] = [
            requestEncoder, ByteToMessageHandler(responseDecoder),
          ]
          let upgrader = NIOWebSocketClientUpgrader(
            automaticErrorHandling: false
          ) { channel, res in
            do {
              let handler = try channel.pipeline.syncOperations.handler(
                type: NIOHTTPClientUpgradeHandler.self
              )
              // Although frame decoder, encoder, and error handler have been added to the pipeline
              // but the order is not what we need. so, we need to reorder them.
              var frameDecoder = try channel.pipeline.syncOperations.handler(
                type: ByteToMessageHandler<WebSocketFrameDecoder>.self
              )
              channel.pipeline.removeHandler(frameDecoder, promise: nil)
              frameDecoder = ByteToMessageHandler(WebSocketFrameDecoder(maxFrameSize: 1 << 14))
              try channel.pipeline.syncOperations.addHandler(
                frameDecoder,
                position: .after(handler)
              )

              var frameEncoder = try channel.pipeline.syncOperations.handler(
                type: WebSocketFrameEncoder.self
              )
              channel.pipeline.removeHandler(frameEncoder, promise: nil)
              frameEncoder = WebSocketFrameEncoder()
              try channel.pipeline.syncOperations.addHandler(
                frameEncoder,
                position: .after(handler)
              )

              let errorHandler = WebSocketProtocolErrorHandler()
              try channel.pipeline.syncOperations.addHandler(
                errorHandler,
                position: .after(frameDecoder)
              )

              // To send websocket frame we need a blendor to write `ByteBuffer` to `WebSocektFrame`
              // and read `WebSocketFrame`  to `ByteBuffer`.
              let producer = WebSocketFrameProducer()
              try channel.pipeline.syncOperations.addHandler(
                producer,
                position: .after(errorHandler)
              )

              try channel.pipeline.syncOperations.addClientHandlers(
                position: .after(producer),
                proxy: proxy,
                destinationAddress: destinationAddress
              )

              return channel.pipeline.removeHandler(requestWriter)
            } catch {
              return channel.eventLoop.makeFailedFuture(error)
            }
          }
          let upgradeHandler = NIOHTTPClientUpgradeHandler(
            upgraders: [upgrader],
            httpHandlers: handlers,
            upgradeCompletionHandler: { _ in }
          )
          handlers.append(upgradeHandler)
          handlers.append(requestWriter)

          return channel.pipeline.addHandlers(handlers)
        }

      if proxy.overTls {
        bootstrap = bootstrap.enableTLS()
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

extension ChannelPipeline {

  fileprivate func addClientHandlers(
    position: Position = .last,
    proxy: Proxy,
    destinationAddress: NetAddress
  ) -> EventLoopFuture<Void> {
    if eventLoop.inEventLoop {
      return eventLoop.makeCompletedFuture {
        try syncOperations.addClientHandlers(
          position: position,
          proxy: proxy,
          destinationAddress: destinationAddress
        )
      }
    } else {
      return eventLoop.submit {
        try self.syncOperations.addClientHandlers(
          position: position,
          proxy: proxy,
          destinationAddress: destinationAddress
        )
      }
    }
  }
}

extension ChannelPipeline.SynchronousOperations {

  fileprivate func addClientHandlers(
    position: ChannelPipeline.Position = .last,
    proxy: Proxy,
    destinationAddress: NetAddress
  ) throws {
    switch proxy.protocol {
    case .http:
      return try addHTTPProxyClientHandlers(
        position: position,
        username: proxy.username,
        passwordReference: proxy.passwordReference,
        authenticationRequired: proxy.authenticationRequired,
        preferHTTPTunneling: proxy.prefererHttpTunneling,
        destinationAddress: destinationAddress
      )
    case .socks5:
      return try addSOCKSClientHandlers(
        position: position,
        username: proxy.username,
        passwordReference: proxy.passwordReference,
        authenticationRequired: proxy.authenticationRequired,
        destinationAddress: destinationAddress
      )
    case .shadowsocks:
      return try addSSClientHandlers(
        position: position,
        algorithm: proxy.algorithm,
        passwordReference: proxy.passwordReference,
        destinationAddress: destinationAddress
      )
    case .vmess:
      return try addVMESSClientHandlers(
        position: position,
        authenticationCode: .random(in: 0 ... .max),
        contentSecurity: .encryptByAES128GCM,
        symmetricKey: .init(size: .bits128),
        nonce: .init(),
        user: UUID(uuidString: proxy.username) ?? UUID(),
        commandCode: .tcp,
        destinationAddress: destinationAddress
      )
    }
  }
}