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

import NIO
import NIOHTTP1
import Helpers

enum ClientState: Hashable {
    case inactive
    case waitingForClientGreeting
    case waitingForHTTPHeadPart
    case waitingForHTTPEndPart
    case active
    case error
}

enum ClientAction {
    case waitForMoreData
    case sendGreeting
    case deliverOneHead(head: HTTPResponseHead)
    case deliverOneEnd(headers: HTTPHeaders?)
    case proxyEstablished
}

struct ClientStateMachine {
    
    private var state: ClientState = .inactive
    
    var proxyEstablished: Bool {
        switch state {
            case .active:
                return true
            case .error, .inactive, .waitingForClientGreeting, .waitingForHTTPHeadPart, .waitingForHTTPEndPart:
                return false
        }
    }
    
    var shouldBeginHandshake: Bool  {
        switch state {
            case .inactive:
                return true
            case .active, .error, .waitingForClientGreeting, .waitingForHTTPHeadPart, .waitingForHTTPEndPart:
                return false
        }
    }
    
}

    // MARK: - Incoming
extension ClientStateMachine {
    
    mutating func receiveHTTPPart(_ part: HTTPClientResponsePart) throws -> ClientAction {
        switch part {
            case .head(let head) where state == .waitingForHTTPHeadPart:
                switch head.status.code {
                    case 200..<300:
                            // Any 2xx (Successful) response indicates that the sender (and all
                            // inbound proxies) will switch to tunnel mode immediately after the
                            // blank line that concludes the successful response's header section
                        return .deliverOneHead(head: head)
                    case 407:
                        throw HTTPProxyError.proxyAuthenticationRequired
                    default:
                            // Any response other than a successful response indicates that the tunnel
                            // has not yet been formed and that the connection remains governed by HTTP.
                        throw HTTPProxyError.invalidProxyResponse
                }
            case .end(let headers) where state == .waitingForHTTPEndPart:
                state = .active
                return .deliverOneEnd(headers: headers)
            default:
                state = .error
                throw HTTPProxyError.unexpectedRead
        }
    }
    
}

    // MARK: - Outgoing
extension ClientStateMachine {
    
    mutating func connectionEstablished() throws -> ClientAction {
        guard state == .inactive else {
            throw HTTPProxyError.invalidClientState
        }
        state = .waitingForClientGreeting
        return .sendGreeting
    }
    
    mutating func sendClientGreeting() throws {
        guard state == .waitingForClientGreeting else {
            throw HTTPProxyError.invalidClientState
        }
        state = .waitingForHTTPHeadPart
    }
}
