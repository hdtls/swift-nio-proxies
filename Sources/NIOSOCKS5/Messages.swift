//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2021 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2021 Junfeng Zhang. and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore

/// Sent by the client and received by the server.
enum ClientMessage {

    /// Contains the proposed authentication methods.
    case greeting(Authentication.Method.Request)

    /// Instructs the server of the target host, and the type of connection.
    case request(Request)

    /// Used to respond to server authentication challenges
    case authenticationData(ByteBuffer)
}

/// Sent by the server and received by the client.
enum ServerMessage {

    /// Used by the server to instruct the client of the authentication method to use.
    case selectedAuthenticationMethod(Authentication.Method.Response)

    /// Sent by the server to inform the client that establishing the proxy to the target
    /// host succeeded or failed.
    case response(Response)

    /// Used when authenticating to send server challenges to the client.
    case authenticationData(ByteBuffer, complete: Bool)
}