//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2021 Junfeng Zhang and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import HTTPTypes

public struct NEHTTPError: Error, Equatable {

  public enum Code: Equatable, Sendable {
    case badRequest
    case proxyAuthenticationRequired
    case requestTimeout
    case unsupportedAddress
    case channelInactive
    case unacceptableStatus(HTTPResponse.Status)
    case unacceptableRead
    case userCancelled
  }
  /// The code this error will return.
  public var code: Code

  /// A localized message describing what error occurred.
  public var errorDescription: String?

  /// A localized message describing the reason for the failure.
  public var failureReason: String?

  /// A localized message describing how one might recover from the failure.
  public var recoverySuggestion: String?

  init(
    code: Code,
    errorDescription: String? = nil,
    failureReason: String? = nil,
    recoverySuggestion: String? = nil
  ) {
    self.code = code
    self.errorDescription = errorDescription
    self.failureReason = failureReason
    self.recoverySuggestion = recoverySuggestion
  }
}

extension NEHTTPError {

  public static var badRequest: NEHTTPError {
    //    let httpFields: HTTPHeaders = ["Connection": "close", "Content-Length": "0"]
    return .init(code: .badRequest)
  }

  public static var proxyAuthenticationRequired: NEHTTPError {
    // TODO: Provides information about the authentication scheme
    //    let httpFields: HTTPHeaders = ["Proxy-Authenticate" : "Basic realm=Access token"]
    //    let httpFields: HTTPHeaders = ["Content-Length": "0"]
    return .init(code: .proxyAuthenticationRequired)
  }

  public static var requestTimeout: NEHTTPError {
    //    let httpFields: HTTPHeaders = ["Connection": "close", "Content-Length": "0"]
    return .init(code: .requestTimeout)
  }
}
