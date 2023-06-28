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
import NEAppEssentials
import NEHTTP
import NEMisc
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

struct RejectByRuleError: Error {}

/// RejectPolicy will reject connection to the destination.
public struct RejectPolicy: ConnectionPolicyRepresentation {

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
public struct RejectTinyGifPolicy: ConnectionPolicyRepresentation {

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

public struct ProxyPolicy: ConnectionPolicyRepresentation {

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
          ) { channel, _ in
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
        contentSecurity: .aes128Gcm,
        user: UUID(uuidString: proxy.username) ?? UUID(),
        commandCode: .tcp,
        destinationAddress: destinationAddress
      )
    }
  }
}

/// ConnectionPolicyRepresentation coding wrapper.
public struct AnyConnectionPolicy: Codable, Hashable, Sendable {

  public var name: String {
    base.name
  }

  public var destinationAddress: NetAddress?

  /// The actual policy value.
  public var base: any ConnectionPolicyRepresentation

  /// Initialize an instance of `AnyConnectionPolicy` with specified base value.
  init(_ base: any ConnectionPolicyRepresentation) {
    self.base = base
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    let name = try container.decode(String.self, forKey: .name)
    let rawValue = try container.decode(String.self, forKey: .type)
    switch rawValue {
    case "direct":
      base = DirectPolicy(name: name)
    case "reject":
      base = RejectPolicy(name: name)
    case "reject-tinygif":
      base = RejectTinyGifPolicy(name: name)
    default:
      let proxy = try container.decode(Proxy.self, forKey: .proxy)
      base = ProxyPolicy(name: name, proxy: proxy)
    }
  }

  enum CodingKeys: CodingKey {
    case name
    case type
    case proxy
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(base.name, forKey: .name)
    switch base {
    case is DirectPolicy:
      try container.encode("direct", forKey: .type)
    case is RejectPolicy:
      try container.encode("reject", forKey: .type)
    case is RejectTinyGifPolicy:
      try container.encode("reject-tinygif", forKey: .type)
    case let policy as ProxyPolicy:
      try container.encode(policy.proxy.protocol.rawValue, forKey: .type)
      try container.encodeIfPresent(policy.proxy, forKey: .proxy)
    default:
      fatalError("Unsupported policy \(base).")
    }
  }

  public static func == (lhs: AnyConnectionPolicy, rhs: AnyConnectionPolicy) -> Bool {
    AnyHashable(lhs.base) == AnyHashable(rhs.base)
  }

  public func hash(into hasher: inout Hasher) {
    hasher.combine(AnyHashable(base))
  }
}

extension AnyConnectionPolicy: ConnectionPolicyRepresentation {
  public func makeConnection(logger: Logger, on eventLoop: EventLoop) -> EventLoopFuture<Channel> {
    base.makeConnection(logger: logger, on: eventLoop)
  }
}
