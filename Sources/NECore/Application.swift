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
import NEDNS
import NEHTTP
import NEHTTPMitM
import NEMisc
import NESOCKS
import NIOCore
import NIOExtras
import NIOHTTP1
import NIOHTTPCompression
import NIOPosix
import NIOSSL

#if canImport(Network) && ENABLE_NIO_TRANSPORT_SERVICES
import NIOTransportServices

typealias ServerBootstrap = NIOTransportServices.NIOTSListenerBootstrap
#else
typealias ServerBootstrap = NIOPosix.ServerBootstrap
#endif

/// A Netbot is an easy way to create network proxy servers.
///
/// For current version we support start HTTP and SOCKS as local proxy servers if possible.
final public class Netbot: @unchecked Sendable {

  private let profile: Profile

  private let logger: Logger

  private let eventLoopGroup: EventLoopGroup

  /// The outbound mode control how requests will be process.
  public var outboundMode: OutboundMode {
    get { $mutableState.outboundMode }
    set { $mutableState.outboundMode = newValue }
  }

  /// A boolean value indicate whether HTTP capture should be enabled, default is false.
  ///
  /// Enabling HTTP capture will reduce performance.
  public var isHTTPCaptureEnabled: Bool {
    get { $mutableState.isHTTPCaptureEnabled }
    set { $mutableState.isHTTPCaptureEnabled = newValue }
  }

  /// A boolean value indicate whether HTTP MitM should be enabled, default is false.
  ///
  /// Enabling HTTP capture will reduce performance.
  public var isHTTPMitMEnabled: Bool {
    get { $mutableState.isHTTPMitMEnabled }
    set { $mutableState.isHTTPMitMEnabled = newValue }
  }

  private struct MutableState {

    /// The outbound mode control how requests will be process.
    var outboundMode: OutboundMode = .direct

    /// A boolean value indicate whether HTTP capture should be enabled, default is false.
    ///
    /// Enabling HTTP capture will reduce performance.
    var isHTTPCaptureEnabled: Bool = false

    /// A boolean value indicate whether HTTP MitM should be enabled, default is false.
    ///
    /// Enabling HTTP capture will reduce performance.
    var isHTTPMitMEnabled: Bool = false

    var services: [(Channel, ServerQuiescingHelper, EventLoopPromise<Void>)] = []

    var certificatePool: CertificatePool?
  }

  @Protected private var mutableState: MutableState = MutableState()

  private let ruleCache = LRUCache<String, ParsableRule>(capacity: 100)

  private var certificatePool: CertificatePool {
    get throws {
      if $mutableState.certificatePool == nil {
        guard let base64String = profile.manInTheMiddleSettings.base64EncodedP12String else {
          throw NIOSSLError.failedToLoadCertificate
        }
        $mutableState.certificatePool = try CertificatePool(
          base64Encoded: base64String,
          passphrase: profile.manInTheMiddleSettings.passphrase
        )
      }
      return $mutableState.certificatePool!
    }
  }

  /// Initialize an instance of `Netbot` with specified profile logger and outboundMode.
  ///
  /// - Parameters:
  ///   - profile: The `Profile` object contains all settings for this process.
  ///   - logger: The `Logger` object used to log message.
  ///   - outboundMode: The connections outbound mode, default is `.direct`.
  public init(profile: Profile, logger: Logger, outboundMode: OutboundMode = .direct) {
    self.profile = profile
    self.logger = logger
    #if canImport(Network) && ENABLE_NIO_TRANSPORT_SERVICES
    self.eventLoopGroup = NIOTSEventLoopGroup()
    #else
    self.eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
    #endif
    self.mutableState = MutableState(outboundMode: outboundMode)
  }

  /// Run VPN servers and wait for shutdown.
  ///
  /// For current version only HTTP and SOCKS proxy server is supported.
  public func run() async throws {
    let basicSettings = profile.basicSettings

    let queue = DispatchQueue(label: "io.tenbits.Netbot.signal.queue")
    let source = DispatchSource.makeSignalSource(signal: SIGINT, queue: queue)
    source.setEventHandler {
      Task.detached {
        print()
        try await self.shutdownGracefully()
      }
    }
    signal(SIGINT, SIG_IGN)
    source.resume()

    try await withThrowingTaskGroup(of: Void.self) { g in
      if let address = basicSettings.httpListenAddress, let port = basicSettings.httpListenPort {
        g.addTask {
          let (channel, quiesce) = try await self.startVPNTunnel(
            protocol: .http,
            bindAddress: address,
            bindPort: port
          )
          let promise = channel.eventLoop.makePromise(of: Void.self)
          self.$mutableState.write {
            $0.services.append((channel, quiesce, promise))
          }
          try await promise.futureResult.get()
        }
      }

      if let address = basicSettings.socksListenAddress, let port = basicSettings.socksListenPort {
        g.addTask {
          let (channel, quiesce) = try await self.startVPNTunnel(
            protocol: .socks5,
            bindAddress: address,
            bindPort: port
          )
          let promise = channel.eventLoop.makePromise(of: Void.self)
          self.$mutableState.write {
            $0.services.append((channel, quiesce, promise))
          }
          try await promise.futureResult.get()
        }
      }

      try await g.waitForAll()
    }
  }

  /// Start a VPN tunnel for specified protocol.
  /// - Parameters:
  ///   - protocol: The VPN protocol.
  ///   - bindAddress: The address for VPN tunnel to bind on.
  ///   - bindPort: The port for VPN tunnel to bind on.
  /// - Returns: Started VPN tunnel and server quiescing helper pair.
  private func startVPNTunnel(
    protocol: Proxy.`Protocol`,
    bindAddress: String,
    bindPort: Int
  ) async throws -> (Channel, ServerQuiescingHelper) {
    let quiesce = ServerQuiescingHelper(group: eventLoopGroup)

    let bootstrap = ServerBootstrap(group: eventLoopGroup)
      .serverChannelInitializer { channel in
        channel.pipeline.addHandler(
          quiesce.makeServerChannelHandler(channel: channel)
        )
      }
      .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
      .serverChannelOption(ChannelOptions.socketOption(.init(rawValue: SO_REUSEPORT)), value: 1)
      .childChannelInitializer { channel in
        let eventLoop = channel.eventLoop.next()
        let completion: @Sendable (RequestInfo) -> EventLoopFuture<Void> = { req in
          let promise = eventLoop.makePromise(of: Void.self)
          promise.completeWithTask {
            // Create client channel to write data to remote proxy server.
            let peer = try await self.initializePeer(forTarget: req.address, eventLoop: eventLoop)

            try await channel.pipeline.addHandler(
              NIOTLSRecognizer { isTLSConnection, channel in
                let promise = channel.eventLoop.makePromise(of: Void.self)
                promise.completeWithTask {
                  try await self.configureHTTPCapabilitiesPipeline(
                    for: channel,
                    peer: peer,
                    serverHostname: req.address.host,
                    isTLSConnection: isTLSConnection,
                    enableHTTPMitM: self.isHTTPMitMEnabled,
                    enableHTTPCapture: self.isHTTPCaptureEnabled
                  )
                }
                return promise.futureResult
              }
            )
          }
          return promise.futureResult
        }

        switch `protocol` {
        case .http:
          return channel.pipeline.configureHTTPProxyServerPipeline(completion: completion)
        case .socks5:
          return channel.pipeline.configureSOCKSServerPipeline(completion: completion)
        default:
          preconditionFailure()
        }
      }
      .childChannelOption(ChannelOptions.tcpOption(.tcp_nodelay), value: 1)

    let channel = try await bootstrap.bind(host: bindAddress, port: bindPort).get()

    guard let localAddress = channel.localAddress else {
      fatalError(
        "Address was unable to bind. Please check that the socket was not closed or that the address family was understood."
      )
    }

    logger.debug(
      "\(`protocol`.description) proxy server started and listening on \(localAddress)"
    )

    return (channel, quiesce)
  }

  /// Initialize client channel for target on eventLoop.
  private func initializePeer(
    forTarget address: NetAddress,
    eventLoop: EventLoop
  ) async throws -> Channel {
    var fallback: Policy = DirectPolicy(destinationAddress: address)

    guard outboundMode != .direct else {
      return try await fallback.makeConnection(logger: logger, on: eventLoop).get()
    }

    // DNS lookup for `req.address`.
    // This results will be used for rule matching.
    let patterns: [String]
    var startTime = DispatchTime.now()
    switch address {
    case .domainPort(let host, let port):
      let resolver = GetaddrinfoResolver(eventLoop: eventLoop)
      async let a = resolver.initiateAQuery(host: host, port: port).get()
      async let aaaa = resolver.initiateAAAAQuery(host: host, port: port).get()
      let addresses = try await a + aaaa
      patterns = [host] + addresses.compactMap { $0.ipAddress ?? $0.pathname }
    case .socketAddress(let addrinfo):
      guard let ipAddress = addrinfo.ipAddress else {
        guard let pathname = addrinfo.pathname else {
          patterns = []
          break
        }
        patterns = [pathname]
        break
      }
      patterns = [ipAddress]
    }

    logger.info(
      "DNS Lookup end with \(startTime.distance(to: .now()).prettyPrinted).",
      metadata: ["Request": "\(address)"]
    )

    startTime = .now()

    var savedFinalRule: ParsableRule!
    for pattern in patterns {
      if let value = ruleCache.value(forKey: pattern) {
        savedFinalRule = value
      }
    }

    if savedFinalRule == nil {
      for rule in profile.rules {
        guard !patterns.contains(where: rule.match(_:)) else {
          savedFinalRule = rule
          break
        }

        if rule is FinalRule {
          savedFinalRule = rule
        }
      }
    }

    guard let savedFinalRule else {
      return try await fallback.makeConnection(logger: logger, on: eventLoop).get()
    }

    Task {
      patterns.forEach { pattern in
        ruleCache.setValue(savedFinalRule, forKey: pattern)
      }
    }

    logger.info(
      "Rule evaluating - \(savedFinalRule.description)",
      metadata: ["Request": "\(address)"]
    )
    logger.info(
      "Rule evaluating end with \(startTime.distance(to: .now()).prettyPrinted).",
      metadata: ["Request": "\(address)"]
    )

    // Policy evaluating.
    var preferred: String?

    // Check whether there is a `PolicyGroup` with then same name as the rule's policy in
    // `policyGroups`, if group exists use group's `selected` as policy ID else use rule's
    // policy as ID.
    if let g = profile.policyGroups.first(where: { $0.name == savedFinalRule.policy }) {
      preferred = g.policies.first
    } else {
      preferred = savedFinalRule.policy
    }

    // The user may not have preferred policy, so if not
    // we should fallback.
    if let preferred, let first = profile.policies.first(where: { $0.name == preferred }) {
      fallback = first
    }

    logger.info("Policy evaluating - \(fallback.name)", metadata: ["Request": "\(address)"])

    // Create peer channel.
    fallback.destinationAddress = address
    return try await fallback.makeConnection(logger: logger, on: eventLoop).get()
  }

  /// Configure HTTP MitM pipeline and HTTP capture pipeline.
  ///
  /// The HTTP MitM pipeline can only be configured when the `serverHostname` is not nil, the current connection is an https
  /// request and `Netbot` enables the HTTP MitM and HTTP capture capabilities (both `Netbot.isHTTPMitMEnabled` and
  /// `Netbot.isHTTPCapatureEnabled` is  true).
  ///
  /// Also, if `serverHostname` is not included in the hostname that needs to enable HTTP MiTM, the HTTP MitM pipeline will not
  /// be configured too.
  ///
  /// And the HTTP capture only works on plain http request or decrypted https request.
  ///
  /// - Parameters:
  ///   - channel: Server channel.
  ///   - peer: Client channel.
  ///   - serverHostname: The destination hostname.
  ///   - isTLSConnection: A boolean value determines whether this connection is HTTPS connection.
  ///   - enableHTTPMitM: A boolean value determines whether should enable HTTP MitM for this connection.
  ///   - enableHTTPCapture: A boolean value determines whether should enable HTTP capture for this connection.
  private func configureHTTPCapabilitiesPipeline(
    for channel: Channel,
    peer: Channel,
    serverHostname: String?,
    isTLSConnection: Bool,
    enableHTTPMitM: Bool,
    enableHTTPCapture: Bool
  ) async throws {
    guard let serverHostname, isTLSConnection, enableHTTPMitM, enableHTTPCapture else {
      // Because it is not a TLS connection, there is no need to consider the mitm pipeline setup.
      guard !isTLSConnection, enableHTTPCapture else {
        let (localGlue, peerGlue) = GlueHandler.matchedPair()
        try await channel.pipeline.addHandler(localGlue)
        try await peer.pipeline.addHandler(peerGlue)
        return
      }
      try await configureHTTPCapturePipeline(for: channel, peer: peer)
      return
    }

    try await configureHTTPMitMPipeline(for: channel, peer: peer, serverHostname: serverHostname)
    try await configureHTTPCapturePipeline(for: channel, peer: peer)
  }

  /// Configure HTTP MitM pipeline if needed.
  ///
  /// If `Netbot.certCache` does not contains certificates and privateKeys pair, configure will be ignored.
  ///
  /// - Parameters:
  ///   - channel: The server channel that need to configure.
  ///   - peer: The client channel that need to configure.
  ///   - serverHostname: The SNI for SSL/TLS.
  private func configureHTTPMitMPipeline(
    for channel: Channel,
    peer: Channel,
    serverHostname: String
  ) async throws {
    // Find whether need perform HTTP MitM action for this hostname, if value exists, then prepare
    // HTTP MitM pipeline else just return and HTTP capture should also be ignored because in this
    // situation the connection is HTTPS request, capture http body has no effect.
    guard let (certificateChain, privateKey) = try certificatePool.value(forKey: serverHostname)
    else {
      return
    }

    // Set up server channel pipeline to decrypt HTTPS stream.
    var configuration = TLSConfiguration.makeServerConfiguration(
      certificateChain: certificateChain,
      privateKey: privateKey
    )
    configuration.certificateVerification =
      profile.manInTheMiddleSettings.skipCertificateVerification ? .none : .fullVerification
    var context = try NIOSSLContext(configuration: configuration)
    let ssl0 = NIOSSLServerHandler(context: context)
    try await channel.pipeline.addHandler(ssl0)

    // Because we have decrypted HTTPS stream, so we need set up client channel to encode decrypted
    // plain HTTP request to HTTPS request.
    configuration = TLSConfiguration.makeClientConfiguration()
    context = try NIOSSLContext(configuration: configuration)
    let ssl1 = try NIOSSLClientHandler(context: context, serverHostname: serverHostname)
    try await peer.pipeline.addHandler(ssl1)
  }

  /// Configure HTTP capture pipeline at specified position.
  private func configureHTTPCapturePipeline(for channel: Channel, peer: Channel) async throws {
    // As we know HTTP capture only supported for HTTP protocols so we need a
    // `PlainHTTPRecognizer` to recognize if this is HTTP request.
    try await channel.pipeline.addHandler(
      PlainHTTPRecognizer { isHTTPRequest, channel in
        let promise = channel.eventLoop.makePromise(of: Void.self)
        promise.completeWithTask {
          let (localGlue, peerGlue) = GlueHandler.matchedPair()

          guard isHTTPRequest else {
            try await channel.pipeline.addHandler(localGlue)
            try await peer.pipeline.addHandler(peerGlue)
            return
          }

          var handlers: [ChannelHandler] =
            [
              HTTPResponseEncoder(),
              ByteToMessageHandler(HTTPRequestDecoder()),
              HTTPResponseCompressor(),
              HTTPCaptureHandler<HTTPRequestHead>(
                logger: Logger(label: "io.HTTP.capture")
              ),
              HTTPIOTransformer<HTTPRequestHead>(),
              localGlue,
            ]
          try await channel.pipeline.addHandlers(handlers)

          handlers =
            [
              HTTPRequestEncoder(),
              ByteToMessageHandler(HTTPResponseDecoder()),
              NIOHTTPResponseDecompressor(limit: .none),
              HTTPCaptureHandler<HTTPResponseHead>(
                logger: Logger(label: "io.HTTP.capture")
              ),
              HTTPIOTransformer<HTTPResponseHead>(),
              peerGlue,
            ]
          try await peer.pipeline.addHandlers(handlers)
        }
        return promise.futureResult
      }
    )
  }

  /// Shutdown Netbot.
  public func shutdownGracefully() async throws {
    // Wait until all server channel closed.
    try await withThrowingTaskGroup(of: Void.self) { g in
      for (channel, quiesce, promise) in $mutableState.services {
        g.addTask {
          self.logger.trace("Shutting down channel \(channel).")
          quiesce.initiateShutdown(promise: promise)
          try await promise.futureResult.get()
        }
      }

      try await g.waitForAll()
    }

    logger.trace("Shutting down eventLoopGroup \(String(describing: eventLoopGroup)).")
    try await eventLoopGroup.shutdownGracefully()

    logger.trace("Netbot shutdown complete.")
  }

  deinit {
    logger.trace("Netbot deinitialized, goodbye!")
  }
}
