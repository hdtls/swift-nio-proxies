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

/// A Netbot is an easy way to create network proxy servers.
///
/// For current version we support start HTTP and SOCKS as local proxy servers if possible.
final public class Netbot: @unchecked Sendable {

  private let profile: Profile

  private let logger: Logger

  private let eventLoopGroup: EventLoopGroup

  /// The outbound mode control how requests will be process.
  @Protected public var outboundMode: OutboundMode = .direct

  /// A boolean value indicate whether HTTP capture should be enabled, default is false.
  ///
  /// Enabling HTTP capture will reduce performance.
  @Protected public var isHTTPCaptureEnabled: Bool = false

  /// A boolean value indicate whether HTTP MitM should be enabled, default is false.
  ///
  /// Enabling HTTP capture will reduce performance.
  @Protected public var isHTTPMitMEnabled: Bool = false

  @Protected private var quiesces: [(ServerQuiescingHelper, EventLoopPromise<Void>)] = []

  @Protected private var certCache: CertCache?

  /// Initialize an instance of `Netbot` with specified profile logger and outboundMode.
  ///
  /// - Parameters:
  ///   - profile: The `Profile` object contains all settings for this process.
  ///   - logger: The `Logger` object used to log message.
  ///   - outboundMode: The connections outbound mode, default is `.direct`.
  public init(profile: Profile, logger: Logger, outboundMode: OutboundMode = .direct) {
    self.profile = profile
    self.logger = logger
    self.eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
    self.outboundMode = outboundMode
    self.certCache = try? CertCache(manInTheMiddleSettings: profile.manInTheMiddleSettings)
  }

  /// Run VPN servers and wait for shutdown.
  ///
  /// For current version only HTTP and SOCKS proxy server is supported.
  public func run() async throws {
    let basicSettings = profile.basicSettings

    do {
      if let address = basicSettings.httpListenAddress, let port = basicSettings.httpListenPort {
        let (_, quiesce) = try await startVPNTunnel(
          protocol: .http,
          bindAddress: address,
          bindPort: port
        )
        quiesces.append((quiesce, eventLoopGroup.next().makePromise()))
      }

      if let address = basicSettings.socksListenAddress, let port = basicSettings.socksListenPort {
        let (_, quiesce) = try await startVPNTunnel(
          protocol: .socks5,
          bindAddress: address,
          bindPort: port
        )
        quiesces.append((quiesce, eventLoopGroup.next().makePromise()))
      }
    } catch {
      try await eventLoopGroup.shutdownGracefully()
      throw error
    }

    let signalQueue = DispatchQueue(label: "io.tenbits.Netbot.signalHandlingQueue")
    let signalSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: signalQueue)
    signalSource.setEventHandler {
      signalSource.cancel()
      self.logger.trace(
        "received signal, initiating shutdown which should complete after the last request finished."
      )
      self.shutdown()
    }
    signal(SIGINT, SIG_IGN)
    signalSource.resume()

    do {
      for (_, promise) in quiesces {
        try await promise.futureResult.get()
      }
      try await eventLoopGroup.shutdownGracefully()

      logger.trace("Netbot shutdown complete.")
    } catch {
      logger.warning("Shutting down failed: \(error).")
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
      .serverChannelOption(ChannelOptions.backlog, value: 256)
      .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
      .childChannelInitializer { channel in
        let eventLoop = channel.eventLoop.next()

        let channelInitializer: @Sendable (RequestInfo) -> EventLoopFuture<Channel>
        let completion: @Sendable (RequestInfo, Channel, Channel) -> EventLoopFuture<Void>

        channelInitializer = { req in
          let promise = eventLoop.makePromise(of: Channel.self)
          promise.completeWithTask {
            try await self.initializePeer(
              forTarget: req.address,
              eventLoop: eventLoop
            )
          }
          return promise.futureResult
        }

        completion = {
          req,
          channel,
          peer in
          channel.pipeline.addHandler(
            NIOTLSRecognizer { ssl, channel in
              let promise = channel.eventLoop.makePromise(of: Void.self)
              promise.completeWithTask {
                try await self.configureHTTPMitmAndCapturePipeline(
                  on: channel,
                  peer: peer,
                  serverHostname: req.address.host,
                  tls: ssl
                )
              }
              return promise.futureResult
            }
          )
        }

        switch `protocol` {
        case .http:
          return channel.pipeline.configureHTTPProxyServerPipeline(
            channelInitializer: channelInitializer,
            completion: completion
          )
        case .socks5:
          return channel.pipeline.configureSOCKSServerPipeline(
            channelInitializer: channelInitializer,
            completion: completion
          )
        default:
          preconditionFailure()
        }
      }
      .childChannelOption(ChannelOptions.socket(IPPROTO_TCP, TCP_NODELAY), value: 1)
      .childChannelOption(
        ChannelOptions.socket(SocketOptionLevel(SOL_SOCKET), SO_REUSEADDR),
        value: SocketOptionValue(1)
      )
      .childChannelOption(ChannelOptions.maxMessagesPerRead, value: 1)

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

    var savedFinalRule: ParsableRule!
    startTime = .now()

    // TODO: Fetch rule from cache.

    if savedFinalRule == nil {
      for rule in profile.rules {
        guard !patterns.contains(where: rule.match(_:)) else {
          savedFinalRule = rule
          break
        }

        // TODO: Store FinalRule unless Profile.rules changed.
        if rule is FinalRule {
          savedFinalRule = rule
        }
      }

      // TODO: Cache rule evaluating result.
    }

    precondition(
      savedFinalRule != nil,
      "Rules defined in profile MUST contain one and only one FinalRule."
    )
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
  /// request (`tls` is true) and `Netbot` enables the HTTP MitM capability (`Netbot.isHTTPMitMEnabled` is true).
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
  ///   - tls: A boolean value indicate whether this connection is HTTPS connection.
  private func configureHTTPMitmAndCapturePipeline(
    on channel: Channel,
    peer: Channel,
    serverHostname: String?,
    tls: Bool
  ) async throws {
    guard isHTTPMitMEnabled, let serverHostname = serverHostname else {
      return
    }

    // If we don't need MitM and HTTP capture just return.
    guard isHTTPCaptureEnabled || tls else {
      return
    }

    guard tls else {
      // This we don't need MitM but need enable HTTP capture.
      let recognizer = try await channel.pipeline.handler(type: NIOTLSRecognizer.self).get()
      let glue = try await peer.pipeline.handler(type: GlueHandler.self).get()
      try await configureHTTPCapturePipeline(
        on: (channel, .after(recognizer)),
        peer: (peer, .after(glue))
      )
      return
    }

    if certCache == nil {
      // Lazy load
      certCache = try CertCache(manInTheMiddleSettings: profile.manInTheMiddleSettings)
    }

    // Find whether need perform HTTP MitM action for this hostname, if value exists, then prepare
    // HTTP MitM pipeline else just return and HTTP capture should also be ignored because in this
    // situation the connection is HTTPS request, capture http body has no effect.
    guard let (certificateChain, privateKey) = try certCache?.value(forKey: serverHostname) else {
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
    let recognizer = try await channel.pipeline.handler(type: NIOTLSRecognizer.self).get()
    try await channel.pipeline.addHandler(ssl0, position: .after(recognizer))

    // Because we have decrypted HTTPS stream, so we need set up client channel to encode decrypted
    // plain HTTP request to HTTPS request.
    configuration = TLSConfiguration.makeClientConfiguration()
    context = try NIOSSLContext(configuration: configuration)
    let ssl1 = try NIOSSLClientHandler(context: context, serverHostname: serverHostname)
    let glue = try await peer.pipeline.handler(type: GlueHandler.self).get()
    try await peer.pipeline.addHandler(ssl1, position: .before(glue))

    guard isHTTPCaptureEnabled else {
      return
    }

    try await configureHTTPCapturePipeline(
      on: (channel, .after(ssl0)),
      peer: (peer, .after(ssl1))
    )
  }

  /// Configure HTTP capture pipeline at specified position.
  private func configureHTTPCapturePipeline(
    on master: (channel: Channel, position: ChannelPipeline.Position),
    peer: (channel: Channel, position: ChannelPipeline.Position)
  ) async throws {
    // As we know HTTP capture only supported for HTTP protocols so we need a
    // `PlainHTTPRecognizer` to recognize if this is HTTP request.
    try await master.channel.pipeline.addHandler(
      PlainHTTPRecognizer { http, channel in
        guard http else {
          return channel.eventLoop.makeSucceededVoidFuture()
        }

        let promise = channel.eventLoop.makePromise(of: Void.self)
        promise.completeWithTask {
          let recognizer = try await channel.pipeline.handler(
            type: PlainHTTPRecognizer.self
          ).get()
          var handlers: [ChannelHandler] =
            [
              HTTPResponseEncoder(),
              ByteToMessageHandler(HTTPRequestDecoder()),
              HTTPResponseCompressor(),
              HTTPCaptureHandler<HTTPRequestHead>(
                logger: Logger(label: "io.HTTP.capture")
              ),
              HTTPIOTransformer<HTTPRequestHead>(),
            ]
          try await channel.pipeline.addHandlers(handlers, position: .after(recognizer))

          handlers =
            [
              HTTPRequestEncoder(),
              ByteToMessageHandler(HTTPResponseDecoder()),
              NIOHTTPResponseDecompressor(limit: .none),
              HTTPCaptureHandler<HTTPResponseHead>(
                logger: Logger(label: "io.HTTP.capture")
              ),
              HTTPIOTransformer<HTTPResponseHead>(),
            ]
          try await peer.channel.pipeline.addHandlers(handlers, position: peer.position)
        }
        return promise.futureResult
      },
      position: master.position
    )
  }

  /// Shutdown Netbot.
  ///
  /// Actually, it perform initiate shutdown for `ServerQuiescingHelper`.
  public func shutdown() {
    logger.debug("Netbot shutting down.")
    logger.trace("Shutting down eventLoopGroup \(String(describing: eventLoopGroup)).")

    for (quiesce, promise) in quiesces {
      quiesce.initiateShutdown(promise: promise)
    }
  }

  deinit {
    logger.trace("Netbot deinitialized, goodbye!")
  }
}
