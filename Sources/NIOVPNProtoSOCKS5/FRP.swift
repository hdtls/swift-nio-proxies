//===----------------------------------------------------------------------===//
//
// This source file is part of the swift-nio-Netbot open source project
//
// Copyright © 2019 Netbot Ltd. and the swift-nio-Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIO

public protocol RFC1918 {
    /// Procedure for TCP-based clients
    /// Write a version identifier/method selection message
    ///
    /// - Parameter context: The `ChannelHandlerContext` which this `ChannelHandler` belongs to.
    func writeHMsg(context: ChannelHandlerContext)

    /// Procedure for TCP-based clients
    /// Receive METHOD selection message
    ///
    /// - Parameters:
    ///   - context: The `ChannelHandlerContext` which this `ChannelHandler` belongs to.
    ///   - byteBuffer: The METHOD selection message byteBuffer.
    func recvHMsg(context: ChannelHandlerContext, byteBuffer: inout ByteBuffer) throws

    /// Producing AUTH negotiation message
    /// Write AUTH message
    ///
    /// - Parameter context: The `ChannelHandlerContext` which this `ChannelHandler` belongs to.
    func writeAMsg(context: ChannelHandlerContext)


    /// Producing AUTH negotiation message
    /// Receive AUTH message
    ///
    /// - Parameter context: The `ChannelHandlerContext` which this `ChannelHandler` belongs to.
    /// - Parameter byteBuffer: The AUTH METHOD message byteBuffer
    func recvAMsg(context: ChannelHandlerContext, byteBuffer: inout ByteBuffer) throws


    /// Producing relative REQ/REP
    /// Write REQ/REP message to remote
    ///
    /// - Parameter context: The `ChannelHandlerContext` which this `ChannelHandler` belongs to.
    func writeRELMsg(context: ChannelHandlerContext)

    /// Producing relative REQ/REP
    /// Receive REQ/REP message
    /// 
    /// - Parameter context: The `ChannelHandlerContext` which this `ChannelHandler` belongs to.
    /// - Parameter byteBuffer: The REQ/REP message byteBuffer.
    func recvRELMsg(context: ChannelHandlerContext, byteBuffer: inout ByteBuffer) throws
}

public protocol RFC1919 {

    /// Producing Username/Password AUTH
    /// Write U/P message
    ///
    /// - Parameter context: The `ChannelHandlerContext` which this `ChannelHandler` belongs to.
    func writeBasicAMsg(context: ChannelHandlerContext)

    /// Producing Username/Password AUTH
    /// Receive U/P message
    ///
    /// - Parameter context: The `ChannelHandlerContext` which this `ChannelHandler` belongs to.
    /// - Parameter byteBuffer: The REQ/REP message byteBuffer.
    func recvBasicAMsg(context: ChannelHandlerContext, byteBuffer: inout ByteBuffer) throws
}
