import NIO
import NIOHTTP1
import Logging
import Helpers

public final class HTTP1ServerCONNECTTunnelHandler: ChannelInboundHandler, RemovableChannelHandler {
    
    public typealias InboundIn = HTTPServerRequestPart
    public typealias OutboundOut = HTTPServerResponsePart
    
    private var state: ServerStateMachine
    
        /// The task uri for truly http request. this value is updated after  `head` part received.
    private var uri: String?
    
    /// When a proxy request is received, we will send a new request to the target server.
    /// During the request is established, we need to cache the proxy request data.
    private var readBuffers = MarkedCircularBuffer<NIOAny>.init(initialCapacity: 2)
            
    public let logger: Logger
        
    public let completion: (String) -> EventLoopFuture<Channel>
        
    public init(logger: Logger = .init(label: "com.netbot.http-tunnel-logging"), completion: @escaping (String) -> EventLoopFuture<Channel>) {
        self.logger = logger
        self.completion = completion
        self.state = ServerStateMachine()
    }
    
    public func handlerAdded(context: ChannelHandlerContext) {
        beginHandshake(context: context)
    }
    
    public func channelActive(context: ChannelHandlerContext) {
        beginHandshake(context: context)
    }
    
    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard !state.shouldBufferRead, readBuffers.isEmpty else {
            if readBuffers.isEmpty {
                context.fireChannelRead(data)
            } else {
                readBuffers.append(data)
            }
            return
        }
        
        do {
            let action = try state.receiveHTTPPart(unwrapInboundIn(data))
            try handleAction(action, context: context)
        } catch {
            deliverOneError(error, context: context)
        }
    }
    
    public func handlerRemoved(context: ChannelHandlerContext) {
            // We're being removed from the pipeline. If we have buffered events, deliver them.
        guard state.proxyEstablished, !readBuffers.isEmpty else {
            return
        }
        emptyInboundBuffer(context: context)
    }
}

extension HTTP1ServerCONNECTTunnelHandler {
    
    private func beginHandshake(context: ChannelHandlerContext) {
        guard context.channel.isActive else {
            return
        }
        do {
            try state.connectionEstablished()
        } catch {
            deliverOneError(error, context: context)
        }
    }
    
    private func handleAction(_ action: ServerAction, context: ChannelHandlerContext) throws {
        switch action {
            case .deliverOneHTTPRequestHeadPart(head: let head):
                try handleHTTPHeadPartReceive(head)
            case .deliverOneHTTPRequestEndPart(headers: let headers):
                try handleHTTPEndPartReceive(headers, context: context)
        }
    }
    
    private func handleHTTPHeadPartReceive(_ head: HTTPRequestHead) throws {
        logger.info("\(head.method) \(head.uri) \(head.version)")
        
        guard head.method == .CONNECT else {
            logger.debug("unsupported HTTP proxy method: \(head.method)")
            throw HTTPProxyError.unsupportedHTTPProxyMethod
        }
        
        uri = head.uri
    }
    
    private func handleHTTPEndPartReceive(_ headers: HTTPHeaders?, context: ChannelHandlerContext) throws {
            // New request is complete. We don't want any more data from now on.
        context.pipeline.handler(type: ByteToMessageHandler<HTTPRequestDecoder>.self)
            .whenSuccess { httpDecoder in
                context.pipeline.removeHandler(httpDecoder, promise: nil)
            }
        
        let client = completion(uri!)
        
        client.whenSuccess { channel in
            self.handleRemoteConnect(peerChannel: channel, context: context)
        }
        
        client.whenFailure { error in
            self.deliverOneError(error, context: context)
        }
    }
    
    private func handleRemoteConnect(peerChannel: Channel, context: ChannelHandlerContext) {
        do {
            try state.sendServerGreeting()
        } catch {
            deliverOneError(error, context: context)
        }
        
            // Ok, upgrade has completed! We now need to begin the upgrade process.
            // First, send the 200 message.
            // This content-length header is MUST NOT, but we need to workaround NIO's insistence that we set one.
        let headers = HTTPHeaders([("Content-Length", "0")])
        let head = HTTPResponseHead(version: .http1_1, status: .ok, headers: headers)
        logger.info("sending establish message to: \(peerChannel.remoteAddress!)...")
        
        context.write(wrapOutboundOut(.head(head)), promise: nil)
        context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
        
        context.pipeline.handler(type: HTTPResponseEncoder.self)
            .whenSuccess { httpEncoder in
                context.pipeline.removeHandler(httpEncoder, promise: nil)
            }
        
            // Now we need to glue our channel and the peer channel together.
        let (localGlue, peerGlue) = GlueHandler.matchedPair()
        context.channel.pipeline.addHandler(localGlue)
            .and(peerChannel.pipeline.addHandler(peerGlue))
            .whenComplete { result in
                switch result {
                    case .success(_):
                        context.pipeline.removeHandler(self, promise: nil)
                        self.emptyInboundBuffer(context: context)
                    case .failure(let error):
                            // Close connected peer channel before closing our channel.
                        self.deliverOneError(error, context: context)
                }
            }
    }
    
    private func emptyInboundBuffer(context: ChannelHandlerContext) {
        while readBuffers.hasMark {
            let buffer = readBuffers.removeFirst()
            context.write(buffer, promise: nil)
        }
        context.flush()
        
        while !readBuffers.isEmpty {
            context.write(readBuffers.removeFirst(), promise: nil)
        }
    }
    
    private func deliverOneError(_ error: Error, context: ChannelHandlerContext) {
        logger.error("\(error)")
        context.close(promise: nil)
        context.fireErrorCaught(error)
    }
    
}
