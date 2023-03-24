//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2021 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

/// Wrapper for SOCKS protcol error.
public enum SOCKSError: Error {

  /// The protocol version was something other than *5*. Note that
  /// we currently only supported SOCKv5.
  case unsupportedProtocolVersion

  ///  The SOCKS server failed to connect to the target host.
  public enum ReplyFailureReason: Sendable {

    /// The SOCKS server encountered an internal failure.
    case generalSOCKSServerFailure

    /// The connection to the host was not allowed.
    case connectionNotAllowedByRuleset

    /// The host network is not reachable.
    case networkUnreachable

    /// The target host was not reachable.
    case hostUnreachable

    /// The connection tot he host was refused
    case connectionRefused

    /// The host address's TTL has expired.
    case tTLExpired

    /// The provided command is not supported.
    case commandNotSupported

    /// The provided address type is not supported.
    case addressTypeNotSupported

    case unassigned
  }

  case replyFailed(reason: ReplyFailureReason)

  /// The client or server receieved data when it did not expect to.
  case unexpectedRead

  public enum AuthenticationFailureReason: Sendable {
    /// The authentication credentials is incorrect.
    case badCredentials

    case unsupported

    /// The client and server were unable to agree on an authentication method.
    case noAcceptableMethod
  }

  case authenticationFailed(reason: AuthenticationFailureReason)
}

extension SOCKSError.ReplyFailureReason {
  static func parse(_ reply: Response.Reply) -> Self {
    switch reply {
    case .generalSOCKSServerFailure:
      return .generalSOCKSServerFailure
    case .notAllowed:
      return .connectionNotAllowedByRuleset
    case .networkUnreachable:
      return .networkUnreachable
    case .hostUnreachable:
      return .hostUnreachable
    case .refused:
      return .connectionRefused
    case .ttlExpired:
      return .tTLExpired
    case .commandUnsupported:
      return .commandNotSupported
    case .addressTypeUnsupported:
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
    case .tTLExpired:
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
    case .unsupported:
      return "METHOD specific negotiation not implemented."
    case .badCredentials:
      return "METHOD specific negotiation failed, incorrect username or password"
    case .noAcceptableMethod:
      return "Unable to agree on an authentication method."
    }
  }
}

extension SOCKSError: CustomStringConvertible {
  public var description: String {
    switch self {
    case .unsupportedProtocolVersion:
      return "Unsupported SOCKS protocol version."
    case .replyFailed(let reason):
      return reason.localizedDescription
    case .authenticationFailed(let reason):
      return reason.localizedDescription
    case .unexpectedRead:
      return "Unexpected read data."
    }
  }
}
