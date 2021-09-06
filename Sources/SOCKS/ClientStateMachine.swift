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

import NIO

private enum ClientState: Hashable {
    case inactive
    case waitingForClientGreeting
    case waitingForAuthenticationMethod(ClientGreeting)
    case waitingForClientAuthentication
    case waitingForServerAuthenticationResponse
    case waitingForClientRequest
    case waitingForServerResponse(Request)
    case active
    case error
}

enum ClientAction: Hashable {
    case waitForMoreData
    case sendGreeting
    case sendAuthentication
    case sendRequest
    case proxyEstablished
}

struct ClientStateMachine {

    private var state: ClientState
    
    var proxyEstablished: Bool {
        switch state {
        case .active:
            return true
            case .error, .inactive, .waitingForAuthenticationMethod, .waitingForClientAuthentication, .waitingForServerAuthenticationResponse, .waitingForClientGreeting, .waitingForClientRequest, .waitingForServerResponse:
            return false
        }
    }
    
    var shouldBeginHandshake: Bool  {
        switch state {
        case .inactive:
            return true
            case .active, .error, .waitingForAuthenticationMethod, .waitingForClientAuthentication, .waitingForServerAuthenticationResponse, .waitingForClientGreeting, .waitingForClientRequest, .waitingForServerResponse:
            return false
        }
    }
    
    init() {
        state = .inactive
    }
    
}

// MARK: - Incoming
extension ClientStateMachine {
    
    mutating func receiveBuffer(_ buffer: inout ByteBuffer) throws -> ClientAction {
        do {
            switch state {
            case .waitingForAuthenticationMethod(let greeting):
                guard let action = try handleSelectedAuthenticationMethod(&buffer, greeting: greeting) else {
                    return .waitForMoreData
                }
                return action
            case .waitingForServerAuthenticationResponse:
                guard let action = try handleAuthentication(&buffer) else {
                    return .waitForMoreData
                }
                return action
            case .waitingForServerResponse(let request):
                guard let action = try handleServerResponse(&buffer, request: request) else {
                    return .waitForMoreData
                }
                return action
            case .active, .error, .inactive, .waitingForClientGreeting, .waitingForClientAuthentication, .waitingForClientRequest:
                throw SOCKSError.unexpectedRead
            }
        } catch {
            state = .error
            throw error
        }
    }
    
    mutating func handleSelectedAuthenticationMethod(_ buffer: inout ByteBuffer, greeting: ClientGreeting) throws -> ClientAction? {
        return try buffer.parseUnwindingIfNeeded { buffer -> ClientAction? in
            guard let selected = try buffer.readMethodSelection() else {
                return nil
            }
            guard greeting.methods.contains(selected.method) else {
                throw SOCKSError.invalidAuthenticationSelection(selected.method)
            }
                
            // we don't current support any form of authentication
            return authenticate(&buffer, method: selected.method)
        }
    }
    
    mutating func handleAuthentication(_ buffer: inout ByteBuffer) throws -> ClientAction? {
        return try buffer.parseUnwindingIfNeeded { buffer -> ClientAction? in
            guard let auth = try buffer.readUsernamePasswordAuthenticationResponse() else {
                return nil
            }
            
            guard auth.isSuccess else {
                throw SOCKSError.authenticationFailed(reason: .incorrectUsernameOrPassword)
            }
            
            state = .waitingForClientRequest
            return .sendRequest
        }
    }
    
    mutating func handleServerResponse(_ buffer: inout ByteBuffer, request: Request) throws -> ClientAction? {
        return try buffer.parseUnwindingIfNeeded { buffer -> ClientAction? in
            guard let response = try buffer.readServerResponse() else {
                return nil
            }
            guard response.reply == .succeeded else {
                throw SOCKSError.replyFailed(reason: .withReply(response.reply))
            }
            state = .active
            return .proxyEstablished
        }
    }
    
    mutating func authenticate(_ buffer: inout ByteBuffer, method: AuthenticationMethod) -> ClientAction {
        precondition(method == .noRequired || method == .usernamePassword, "No authentication mechanism is supported. Use .noRequired only.")
        
        switch method {
            case .noRequired:
                state = .waitingForClientRequest
                return .sendRequest
            case .usernamePassword:
                state = .waitingForClientAuthentication
                return .sendAuthentication
            default:
                    // we don't currently support any other authentication
                    // so assume all is fine, and instruct the client
                    // to send the request
                state = .waitingForClientRequest
                return .sendRequest
        }
    }
    
}

// MARK: - Outgoing
extension ClientStateMachine {
    
    mutating func connectionEstablished() throws -> ClientAction {
        guard state == .inactive else {
            throw SOCKSError.invalidClientState
        }
        state = .waitingForClientGreeting
        return .sendGreeting
    }

    mutating func sendClientGreeting(_ greeting: ClientGreeting) throws {
        guard state == .waitingForClientGreeting else {
            throw SOCKSError.invalidClientState
        }
        state = .waitingForAuthenticationMethod(greeting)
    }
    
    mutating func sendClientAuthentication(_ auth: UsernamePasswordAuthentication) throws {
        guard state == .waitingForClientAuthentication else {
            throw SOCKSError.invalidClientState
        }
        state = .waitingForServerAuthenticationResponse
    }

    mutating func sendClientRequest(_ request: Request) throws {
        guard state == .waitingForClientRequest else {
            throw SOCKSError.invalidClientState
        }
        state = .waitingForServerResponse(request)
    }
    
}
