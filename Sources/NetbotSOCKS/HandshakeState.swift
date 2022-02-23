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

import Foundation

enum HandshakeState: Equatable {
    case idle
    case greeting
    case authorizing
    case addressing
    case establish
    case active
    case failed
    
    var isActive: Bool {
        self == .active
    }
    
    mutating func idle() throws {
        guard self == .idle else {
            throw SOCKSError.invalidServerState
        }
        self = .greeting
    }
    
    mutating func greeting(_ method: AuthenticationMethod) throws {
        guard self == .greeting else {
            throw SOCKSError.invalidServerState
        }
        self = method == .noRequired ? .addressing : .authorizing
    }
    
    mutating func authorizing() throws {
        guard self == .authorizing else {
            throw SOCKSError.invalidServerState
        }
        self = .addressing
    }
    
    mutating func addressing() throws {
        guard self == .addressing else {
            throw SOCKSError.invalidServerState
        }
        self = .establish
    }
    
    mutating func establish() throws {
        guard self == .establish else {
            throw SOCKSError.invalidServerState
        }
        self = .active
    }
    
    mutating func failure() {
        self = .failed
    }
}
