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

import Foundation

public enum SOCKS5ProxyError: Error, Equatable {

    public enum SerializationFailureReason {
        case needMoreBytes
        case invalidInputBytes
    }

    public enum AuthenticationFailureReason {
        case incorrectUsernameOrPassword
        case noMethodImpl
    }

    public enum ReplyFailureReason {
        case generalSOCKSServerFailure
        case connectionNotAllowedByRuleset
        case networkUnreachable
        case hostUnreachable
        case connectionRefused
        case TTLExpired
        case commandNotSupported
        case addressTypeNotSupported
        case unassigned
    }

    case disconnected
    case serializeFailed(reason: SerializationFailureReason)
    case replyFailed(reason: ReplyFailureReason)
    case authenticationFailed(reason: AuthenticationFailureReason)
}

extension SOCKS5ProxyError.SerializationFailureReason {
    var localizedDescription: String {
        switch self {
        case .invalidInputBytes:
            return "Response could not be serialized, input byte is not valid."
        case .needMoreBytes:
            return "Response could not be serialized, need more bytes."
        }
    }
}

extension SOCKS5ProxyError.AuthenticationFailureReason {
    var localizedDescription: String {
        switch self {
        case .noMethodImpl:
            return "METHOD specific negotiation not implemented."
        case .incorrectUsernameOrPassword:
            return "METHOD specific negotiation failed, incorrect username or password"
        }
    }
}

extension SOCKS5ProxyError.ReplyFailureReason {
    static func withReply(_ reply: Reply?) -> Self {
        switch reply {
        case .generalSOCKSServerFailure:
            return .generalSOCKSServerFailure
        case .connectionNotAllowedByRuleset:
            return .connectionNotAllowedByRuleset
        case .networkUnreachable:
            return .networkUnreachable
        case .hostUnreachable:
            return .hostUnreachable
        case .connectionRefused:
            return .connectionRefused
        case .TTLExpired:
            return .TTLExpired
        case .commandNotSupported:
            return .commandNotSupported
        case .addressTypeNotSupported:
            return .addressTypeNotSupported
        default:
            return .unassigned
        }
    }
}

extension SOCKS5ProxyError.ReplyFailureReason {
    var localizedDescription: String {
        switch self {
        case .generalSOCKSServerFailure:
            return "General SOCKS server failure."
        case .connectionNotAllowedByRuleset:
            return "Connection not allowed by ruleset."
        case .networkUnreachable:
            return "Network unreachable."
        case .hostUnreachable:
            return "Host unreachable."
        case .connectionRefused:
            return "Connection refused."
        case .TTLExpired:
            return "TTL expired."
        case .commandNotSupported:
            return "Command not supported."
        case .addressTypeNotSupported:
            return "Address type not supported."
        case .unassigned:
            return "Unassigned."
        }
    }
}

extension SOCKS5ProxyError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .disconnected:
            return "Disconnected."
        case .serializeFailed(reason: let reason):
            return reason.localizedDescription
        case .authenticationFailed(reason: let reason):
            return reason.localizedDescription
        case .replyFailed(reason: let reason):
            return reason.localizedDescription
        }
    }
}
