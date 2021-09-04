import NIOCore
import Logging

extension ChannelPipeline {
    
    public func addSSClientHandlers(logger: Logger = .init(label: "com.netbot.shadowsocks"),
                                    taskAddress: Endpoint,
                                    configuration: ProxyConfiguration,
                                    position: Position = .last) -> EventLoopFuture<Void> {
        let eventLoopFuture: EventLoopFuture<Void>
        
        if eventLoop.inEventLoop {
            let result = Result<Void, Error> {
                try syncOperations.addSSClientHandlers(logger: logger,
                                                       taskAddress: taskAddress,
                                                       configuration: configuration,
                                                       position: position)
            }
            eventLoopFuture = eventLoop.makeCompletedFuture(result)
        } else {
            eventLoopFuture = eventLoop.submit({
                try self.syncOperations.addSSClientHandlers(logger: logger,
                                                            taskAddress: taskAddress,
                                                            configuration: configuration,
                                                            position: position)
            })
        }
        
        return eventLoopFuture
    }
}

extension ChannelPipeline.SynchronousOperations {
    
    public func addSSClientHandlers(logger: Logger = .init(label: "com.netbot.shadowsocks"),
                                    taskAddress: Endpoint,
                                    configuration: ProxyConfiguration,
                                    position: ChannelPipeline.Position = .last) throws {
        eventLoop.assertInEventLoop()
        let inboundDecoder = SSAEADClientResponseDecoder(configuration: configuration)
        let outboundEncoder = SSAEADEncoder(taskAddress: taskAddress, configuration: configuration)
        let handlers: [ChannelHandler] = [ByteToMessageHandler(inboundDecoder), MessageToByteHandler(outboundEncoder)]
        try addHandlers(handlers, position: position)
    }
}
