import NIOCore
import Logging

extension ChannelPipeline {
    
    public func addSSClientHandlers(logger: Logger = .init(label: "com.netbot.shadowsocks"),
                                    taskAddress: Endpoint,
                                    secretKey: String,
                                    position: Position = .last) -> EventLoopFuture<Void> {
        let eventLoopFuture: EventLoopFuture<Void>
        
        if eventLoop.inEventLoop {
            let result = Result<Void, Error> {
                try syncOperations.addSSClientHandlers(logger: logger,
                                                       taskAddress: taskAddress,
                                                       secretKey: secretKey,
                                                       position: position)
            }
            eventLoopFuture = eventLoop.makeCompletedFuture(result)
        } else {
            eventLoopFuture = eventLoop.submit({
                try self.syncOperations.addSSClientHandlers(logger: logger,
                                                            taskAddress: taskAddress,
                                                            secretKey: secretKey,
                                                            position: position)
            })
        }
        
        return eventLoopFuture
    }
}

extension ChannelPipeline.SynchronousOperations {
    
    public func addSSClientHandlers(logger: Logger = .init(label: "com.netbot.shadowsocks"),
                                    taskAddress: Endpoint,
                                    secretKey: String,
                                    position: ChannelPipeline.Position = .last) throws {
        eventLoop.assertInEventLoop()
        let inboundDecoder = SSAEADClientResponseDecoder(secretKey: secretKey)
        let outboundEncoder = SSAEADEncoder(taskAddress: taskAddress, secretKey: secretKey)
        let handlers: [ChannelHandler] = [ByteToMessageHandler(inboundDecoder), MessageToByteHandler(outboundEncoder)]
        try addHandlers(handlers, position: position)
    }
}