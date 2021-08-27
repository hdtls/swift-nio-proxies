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

enum ServerState {
    case inactive
    case waitingForClientGreeting
    case waitingForClientGreetingEnd
    case waitingToSendGreeting
    case active
    case error
}

enum ServerAction {
    case deliverOneHTTPRequestHeadPart(head: HTTPRequestHead)
    case deliverOneHTTPRequestEndPart(headers: HTTPHeaders?)
}

struct ServerStateMachine {
    
    private var state: ServerState
    
    var proxyEstablished: Bool {
        return state == .active
    }
    
    var shouldBufferRead: Bool {
        return state == .waitingToSendGreeting || state == .active
    }
    
    init() {
        self.state = .inactive
    }
}

    // MARK: - Inbound
extension ServerStateMachine {
    
    mutating func receiveHTTPPart(_ part: HTTPServerRequestPart) throws -> ServerAction {
        switch part {
            case .head(let head) where state == .waitingForClientGreeting:
                state = .waitingForClientGreetingEnd
                return .deliverOneHTTPRequestHeadPart(head: head)
            case .end(let headers) where state == .waitingForClientGreetingEnd:
                state = .waitingToSendGreeting
                return .deliverOneHTTPRequestEndPart(headers: headers)
            default:
                state = .error
                throw HTTPProxyError.unexpectedRead
        }
    }
    
}

    // MARK: - Outbound
extension ServerStateMachine {
    
    mutating func connectionEstablished() throws {
        switch state {
            case .inactive:
                ()
            default:
                throw HTTPProxyError.invalidServerState
        }
        state = .waitingForClientGreeting
    }
    
    mutating func sendServerGreeting() throws {
        if case .waitingToSendGreeting = state {
            state = .active
        } else {
            throw HTTPProxyError.invalidServerState
        }
    }
}
