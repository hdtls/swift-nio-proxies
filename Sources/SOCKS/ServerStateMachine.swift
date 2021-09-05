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
// Copyright (c) 2021 Junfeng Zhang
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIO

enum ServerState: Hashable {
    case inactive
    case waitingForClientGreeting
    case waitingToSendAuthenticationMethod
    case authenticating
    case waitingForClientRequest
    case waitingToSendResponse
    case active
    case error
}

struct ServerStateMachine: Hashable {
    
    private var state: ServerState
    private var authenticationMethod: AuthenticationMethod?
    
    var proxyEstablished: Bool {
        switch state {
        case .active:
            return true
        case .inactive,
             .waitingForClientGreeting,
             .waitingToSendAuthenticationMethod,
             .authenticating,
             .waitingForClientRequest,
             .waitingToSendResponse,
             .error:
            return false
        }
    }
    
    init() {
        state = .inactive
    }
}

// MARK: - Inbound
extension ServerStateMachine {
    
    mutating func receiveBuffer(_ buffer: inout ByteBuffer) throws -> ClientMessage? {
        do {
            switch state {
            case .inactive, .waitingToSendAuthenticationMethod, .waitingToSendResponse, .active, .error:
                throw SOCKSError.unexpectedRead
            case .waitingForClientGreeting:
                return try handleClientGreeting(from: &buffer)
            case .authenticating:
                return handleAuthenticationData(from: &buffer)
            case .waitingForClientRequest:
                return try handleClientRequest(from: &buffer)
            }
        } catch {
            state = .error
            throw error
        }
    }
    
    fileprivate  mutating func handleClientGreeting(from buffer: inout ByteBuffer) throws -> ClientMessage? {
        return try buffer.parseUnwindingIfNeeded { buffer -> ClientMessage? in
            guard let greeting = try buffer.readClientGreeting() else {
                return nil
            }
            state = .waitingToSendAuthenticationMethod
            return .greeting(greeting)
        }
    }
    
    fileprivate mutating func handleClientRequest(from buffer: inout ByteBuffer) throws -> ClientMessage? {
        return try buffer.parseUnwindingIfNeeded { buffer -> ClientMessage? in
            guard let request = try buffer.readClientRequest() else {
                return nil
            }
            state = .waitingToSendResponse
            return .request(request)
        }
    }
    
    fileprivate mutating func handleAuthenticationData(from buffer: inout ByteBuffer) -> ClientMessage? {
        guard let buffer = buffer.readSlice(length: buffer.readableBytes) else {
            return nil
        }
        return .authenticationData(buffer)
    }
    
}

// MARK: - Outbound
extension ServerStateMachine {
    
    mutating func connectionEstablished() throws {
        switch state {
        case .inactive:
            ()
        case .authenticating,
             .waitingForClientGreeting,
             .waitingToSendAuthenticationMethod,
             .waitingForClientRequest,
             .waitingToSendResponse,
             .active,
             .error:
             throw SOCKSError.invalidServerState
        }
        state = .waitingForClientGreeting
    }
    
    mutating func sendAuthenticationMethod(_ selected: SelectedAuthenticationMethod) throws {
        switch state {
        case .waitingToSendAuthenticationMethod:
            ()
        case .inactive,
             .waitingForClientGreeting,
             .authenticating,
             .waitingForClientRequest,
             .waitingToSendResponse,
             .active,
             .error:
             throw SOCKSError.invalidServerState
        }
        
        authenticationMethod = selected.method
        if selected.method == .noRequired {
            state = .waitingForClientRequest
        } else {
            state = .authenticating
        }
    }
    
    mutating func sendServerResponse(_ response: Response) throws {
        switch state {
        case .waitingToSendResponse:
            ()
        case .inactive,
             .waitingForClientGreeting,
             .waitingToSendAuthenticationMethod,
             .waitingForClientRequest,
             .authenticating,
             .active,
             .error:
             throw SOCKSError.invalidServerState
        }
        
        if response.reply == .succeeded {
            state = .active
        } else {
            state = .error
        }
    }
    
    mutating func sendAuthenticationData(_ data: ByteBuffer, complete: Bool) throws {
        switch state {
        case .authenticating:
            break
        case .waitingForClientRequest:
            guard authenticationMethod == .noRequired, complete, data.readableBytes == 0 else {
                throw SOCKSError.invalidServerState
            }
        case .inactive,
             .waitingForClientGreeting,
             .waitingToSendAuthenticationMethod,
             .waitingToSendResponse,
             .active,
             .error:
             throw SOCKSError.invalidServerState
        }
        
        if complete {
            state = .waitingForClientRequest
        }
    }
}
