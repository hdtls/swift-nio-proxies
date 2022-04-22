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

public enum SOCKS5ProxyError: Error, Equatable {

    public enum SerializationFailureReason {
        case needMoreBytes
        case invalidInputBytes
    }

    public enum AuthenticationFailureReason {
        case incorrectUsernameOrPassword
        case noMethodImpl
    }

    case disconnected
    case serializeFailed(reason: SerializationFailureReason)
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

/// Wrapper for SOCKS protcol error.
public enum SOCKSError: Error, Equatable {

    /// The SOCKS client was in a different state to that required.
    case invalidClientState

    /// The SOCKS server was in a different state to that required.
    case invalidServerState

    /// The protocol version was something other than *5*. Note that
    /// we currently only supported SOCKv5.
    case invalidProtocolVersion(actual: UInt8)

    /// Reserved bytes should always be the `NULL` byte *0x00*. Something
    /// else was encountered.
    case invalidReservedByte(actual: UInt8)

    /// SOCKSv5 only supports IPv4 (*0x01*), IPv6 (*0x04*), or FQDN(*0x03*).
    case invalidAddressType(actual: UInt8)

    /// The server selected an authentication method not supported by the client.
    case invalidAuthenticationSelection(AuthenticationMethod)

    /// Missing authentication credential.
    case missingCredential

    ///  The SOCKS server failed to connect to the target host.
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

    case replyFailed(reason: ReplyFailureReason)

    /// The client or server receieved data when it did not expect to.
    case unexpectedRead

    public enum AuthenticationFailureReason {
        case incorrectUsernameOrPassword
        case noMethodImpl
        /// The client and server were unable to agree on an authentication method.
        case noValidAuthenticationMethod
    }

    case authenticationFailed(reason: AuthenticationFailureReason)

}

extension SOCKSError.ReplyFailureReason {
    static func withReply(_ reply: SOCKSServerReply?) -> Self {
        switch reply {
            case SOCKSServerReply.generalSOCKSServerFailure:
                return .generalSOCKSServerFailure
            case SOCKSServerReply.notAllowed:
                return .connectionNotAllowedByRuleset
            case SOCKSServerReply.networkUnreachable:
                return .networkUnreachable
            case SOCKSServerReply.hostUnreachable:
                return .hostUnreachable
            case SOCKSServerReply.refused:
                return .connectionRefused
            case SOCKSServerReply.ttlExpired:
                return .TTLExpired
            case SOCKSServerReply.commandUnsupported:
                return .commandNotSupported
            case SOCKSServerReply.addressTypeUnsupported:
                return .addressTypeNotSupported
            default:
                return .unassigned
        }
    }
}

extension SOCKSError.ReplyFailureReason {
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

extension SOCKSError.AuthenticationFailureReason {
    var localizedDescription: String {
        switch self {
            case .noMethodImpl:
                return "METHOD specific negotiation not implemented."
            case .incorrectUsernameOrPassword:
                return "METHOD specific negotiation failed, incorrect username or password"
            case .noValidAuthenticationMethod:
                return "Unable to agree on an authentication method."
        }
    }
}

extension SOCKSError: CustomStringConvertible {
    public var description: String {
        switch self {
            case .invalidClientState:
                return "Invalid client state."
            case .invalidServerState:
                return "Invalid server state."
            case .invalidProtocolVersion(actual: let version):
                return "Invalid SOCKS protocol version \(version)."
            case .invalidReservedByte(actual: let reserved):
                return "Invalid reserved byte \(reserved)."
            case .invalidAddressType(actual: let type):
                return "Invalid task address type \(type)."
            case .invalidAuthenticationSelection:
                return "Invalid authentication selection."
            case .missingCredential:
                return "Missing authentication credential."
            case .replyFailed(let reason):
                return reason.localizedDescription
            case .authenticationFailed(let reason):
                return reason.localizedDescription
            case .unexpectedRead:
                return "Unexpected read data."
        }
    }
}
