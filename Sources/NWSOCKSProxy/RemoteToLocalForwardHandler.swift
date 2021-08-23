import NIO

class RemoteToLocalForwardHandler: ChannelDuplexHandler {
    typealias InboundIn = NIOAny
    
    typealias OutboundIn = NIOAny
    
    let localChannel: Channel
    
    init(channel: Channel) {
        localChannel = channel
    }
    
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard localChannel.isWritable else {
            return
        }

        _ = localChannel.writeAndFlush(data)
    }
}
