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

public enum HTTPProxyError: Error {
    case invalidClientState
    case invalidServerState
    case invalidProxyResponse
    case invalidHTTPOrdering
    case unsupportedHTTPProxyMethod
    case unexpectedRead
    case proxyAuthenticationRequired
}
