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
import MaxMindDB
import NIOCore
import NIODNS
import NIOExtras
import NIOHTTP1
import NIOHTTPCompression
import NIOHTTPMitM
import NIOHTTPProxy
import NIONetbotMisc
import NIOPosix
import NIOSOCKS5
import NIOSSL

public class App {

    private actor MutableStorage {

        var profile: Profile

        var outboundMode: OutboundMode

        var isHTTPCaptureEnabled: Bool = false

        var isMitmEnabled: Bool = false

        var maxMindDB: MaxMindDB

        var serverQuiesces: [(ServerQuiescingHelper, EventLoopPromise<Void>)]

        init(
            profile: Profile,
            outboundMode: OutboundMode = .direct,
            enableHTTPCapture: Bool = false,
            enableMitm: Bool = false,
            maxMindDB: MaxMindDB
        ) {
            self.profile = profile
            self.outboundMode = outboundMode
            self.isHTTPCaptureEnabled = enableHTTPCapture
            self.isMitmEnabled = enableMitm
            self.maxMindDB = maxMindDB
            self.serverQuiesces = []
        }

        func enableHTTPCapture(_ isEnabled: Bool) {
            isHTTPCaptureEnabled = isEnabled
        }

        func enableHTTPMitM(_ isEnabled: Bool) {
            isMitmEnabled = isEnabled
        }

        func appendServerQuiesces(_ sq: (ServerQuiescingHelper, EventLoopPromise<Void>)) {
            serverQuiesces.append(sq)
        }
    }

    private let logger: Logger

    private let storage: MutableStorage

    private let eventLoopGroup: EventLoopGroup

    private let cache: LRUCache<String, AnyRule> = .init(capacity: 100)

    private var isRunning = true

    public init(
        logger: Logger = .init(label: "io.tenbits.Netbot"),
        profile: Profile,
        outboundMode: OutboundMode = .direct,
        enableHTTPCapture: Bool = false,
        enableMitm: Bool = false,
        maxMindDB: MaxMindDB
    ) {
        self.logger = logger
        self.eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
        self.storage = .init(
            profile: profile,
            outboundMode: outboundMode,
            enableHTTPCapture: enableHTTPCapture,
            enableMitm: enableMitm,
            maxMindDB: maxMindDB
        )
    }

    public func run() async throws {
        do {
            if let address = await storage.profile.general.httpListenAddress,
                let port = await storage.profile.general.httpListenPort
            {
                let (_, quiesce) = try await startVPNTunnel(
                    protocol: .http,
                    bindAddress: address,
                    bindPort: port
                )
                await self.storage.appendServerQuiesces(
                    (quiesce, eventLoopGroup.next().makePromise())
                )
            }

            if let address = await storage.profile.general.socksListenAddress,
                let port = await storage.profile.general.socksListenPort
            {
                let (_, quiesce) = try await startVPNTunnel(
                    protocol: .socks5,
                    bindAddress: address,
                    bindPort: port
                )
                await self.storage.appendServerQuiesces(
                    (quiesce, eventLoopGroup.next().makePromise())
                )
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
            Task {
                await self.shutdown()
            }
        }
        signal(SIGINT, SIG_IGN)
        signalSource.resume()

        do {
            for (_, promise) in await storage.serverQuiesces {
                try await promise.futureResult.get()
            }
            try await eventLoopGroup.shutdownGracefully()

            logger.trace("Netbot shutdown complete.")
        } catch {
            logger.warning("Shutting down failed: \(error).")
        }
    }

    private func startVPNTunnel(
        `protocol`: Proxy.`Protocol`,
        bindAddress: String,
        bindPort: Int
    ) async throws -> (Channel, ServerQuiescingHelper) {
        let quiesce = ServerQuiescingHelper(group: eventLoopGroup)

        let bootstrap = ServerBootstrap(group: eventLoopGroup)
            .serverChannelOption(ChannelOptions.backlog, value: 256)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .serverChannelInitializer { channel in
                channel.pipeline.addHandler(
                    quiesce.makeServerChannelHandler(channel: channel)
                )
            }
            .childChannelInitializer { channel in
                let eventLoop = channel.eventLoop.next()

                switch `protocol` {
                    case .http:
                        return channel.pipeline.configureHTTPProxyServerPipeline { req in
                            let promise = eventLoop.makePromise(of: Channel.self)
                            promise.completeWithTask {
                                try await self.initializePeer(
                                    forTarget: req.address,
                                    eventLoop: eventLoop
                                )
                            }
                            return promise.futureResult
                        } completion: { req, channel, peer in
                            channel.pipeline.addHandler(
                                NIOTLSRecognizer { ssl, channel in
                                    let promise = channel.eventLoop.makePromise(of: Void.self)
                                    promise.completeWithTask {
                                        try await self.configureHTTPMitmAndCapturePipeline(
                                            on: channel,
                                            peer: peer,
                                            serverHostname: req.serverHostname,
                                            tls: ssl
                                        )
                                    }
                                    return promise.futureResult
                                }
                            )
                        }
                    case .socks5:
                        let handler = SOCKS5ServerHandler(
                            username: "",
                            passwordReference: "",
                            authenticationRequired: false
                        ) { address in
                            let promise = channel.eventLoop.next().makePromise(of: Channel.self)
                            promise.completeWithTask {
                                try await self.initializePeer(
                                    forTarget: address,
                                    eventLoop: eventLoop
                                )
                            }
                            return promise.futureResult
                        }
                        return channel.pipeline.addHandler(handler)
                    default:
                        preconditionFailure()
                }
            }
            .childChannelOption(
                ChannelOptions.socket(IPPROTO_TCP, TCP_NODELAY),
                value: SocketOptionValue(1)
            )
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

    private func initializePeer(
        forTarget address: NetAddress,
        eventLoop: EventLoop
    ) async throws -> Channel {

        let profile = await storage.profile

        guard await storage.outboundMode != .direct else {
            return try await DirectPolicy().makeConnection(logger: logger, on: eventLoop).get()
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
                patterns = [host] + addresses.map { $0.ipAddress ?? $0.pathname! }
            case .socketAddress(let addrinfo):
                patterns = [addrinfo.ipAddress ?? addrinfo.pathname!]
        }

        logger.info(
            "DNS Lookup end with \(startTime.distance(to: .now()).prettyPrinted).",
            metadata: ["Request": "\(address)"]
        )

        var savedFinalRule: AnyRule!
        startTime = .now()

        // Fetch rule from LRU cache.
        for pattern in patterns {
            savedFinalRule = await self.cache.value(forKey: pattern)
            if savedFinalRule != nil {
                break
            }
        }

        if savedFinalRule == nil {
            for rule in profile.rules {
                guard !patterns.contains(where: rule.match(_:)) else {
                    savedFinalRule = rule
                    break
                }

                // TODO: Store FinalRule unless Profile.rules changed.
                if rule.type == .final {
                    savedFinalRule = rule
                }
            }

            // Cache rule evaluating result.
            for pattern in patterns {
                await self.cache.setValue(savedFinalRule, forKey: pattern)
            }
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
        var fallback: Policy! = DirectPolicy()

        var preferred: String?

        // Check whether there is a `PolicyGroup`
        // with then same name as the rule's policy in
        // `policyGroups`, if group exists use group's
        // `selected` as policy ID else use rule's policy as ID.
        if let g = profile.policyGroups.first(where: { $0.name == savedFinalRule.policy }) {
            preferred = g.policies.first?.name
        } else {
            preferred = savedFinalRule.policy
        }

        // The user may not have preferred policy, so if not
        // we should fallback.
        if let preferred = preferred {
            fallback = (profile.policies + Builtin.policies).first { $0.name == preferred }
        }

        precondition(
            fallback != nil,
            "Illegal selectable policy groups, all policies group should be one of the policies in same profile."
        )

        logger.info("Policy evaluating - \(fallback.name)", metadata: ["Request": "\(address)"])

        // Create peer channel.
        fallback.destinationAddress = address
        return try await fallback.makeConnection(logger: logger, on: eventLoop).get()
    }

    private func configureHTTPMitmAndCapturePipeline(
        on channel: Channel,
        peer: Channel,
        serverHostname: String,
        tls: Bool
    ) async throws {
        guard await storage.isMitmEnabled else {
            return
        }

        let profile = await storage.profile
        let enableHTTPCapture = await storage.isHTTPCaptureEnabled

        // If we don't need MitM and HTTP capture just return.
        guard tls || enableHTTPCapture else {
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

        // If detect SSL handshake then setup SSL pipeline to decrypt SSL.
        guard let base64EncodedP12String = profile.mitm.base64EncodedP12String else {
            // To enable the HTTP MitM feature, you must provide the corresponding configuration.
            throw NIOSSLError.failedToLoadCertificate
        }

        let store = try CertificateStore(
            passphrase: profile.mitm.passphrase,
            base64EncodedP12String: base64EncodedP12String
        )
        await store.setUpMitMHosts(profile.mitm.hostnames)

        guard let p12 = try await store.certificate(identifiedBy: serverHostname) else {
            return
        }

        let certificateChain = p12.certificateChain.map(NIOSSLCertificateSource.certificate)
        let privateKey = NIOSSLPrivateKeySource.privateKey(p12.privateKey)
        var configuration = TLSConfiguration.makeServerConfiguration(
            certificateChain: certificateChain,
            privateKey: privateKey
        )
        configuration.certificateVerification =
            profile.mitm.skipCertificateVerification ? .none : .fullVerification
        var context = try NIOSSLContext(configuration: configuration)
        let ssl0 = NIOSSLServerHandler(context: context)
        let recognizer = try await channel.pipeline.handler(type: NIOTLSRecognizer.self).get()
        try await channel.pipeline.addHandler(ssl0, position: .after(recognizer))

        // Peer channel pipeline setup.
        configuration = TLSConfiguration.makeClientConfiguration()
        context = try NIOSSLContext(configuration: configuration)
        let ssl1 = try NIOSSLClientHandler(context: context, serverHostname: serverHostname)
        let glue = try await peer.pipeline.handler(type: GlueHandler.self).get()
        try await peer.pipeline.addHandler(ssl1, position: .before(glue))

        guard enableHTTPCapture else {
            return
        }

        try await configureHTTPCapturePipeline(
            on: (channel, .after(ssl0)),
            peer: (peer, .after(ssl1))
        )
    }

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

    public func shutdown() async {
        logger.debug("Netbot shutting down.")
        logger.trace("Shutting down eventLoopGroup \(String(describing: eventLoopGroup)).")

        for (quiesce, promise) in await self.storage.serverQuiesces {
            quiesce.initiateShutdown(promise: promise)
        }
    }

    deinit {
        logger.trace("Netbot deinitialized, goodbye!")
    }
}
