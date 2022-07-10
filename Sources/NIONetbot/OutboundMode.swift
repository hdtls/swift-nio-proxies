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

/// The network outbound mode.
public enum OutboundMode: String, CaseIterable {

    /// Direct mode. In this mode all requests will be sent directly.
    case direct

    /// Global proxy mode. In this mode all requests will be forwarded to a proxy server.
    case proxy

    /// Rule-based model. In this mode all requests will be forwarded base on rule system.
    case rule
}

extension OutboundMode: CustomStringConvertible {

    public var description: String {
        switch self {
            case .direct:
                return "direct mode"
            case .proxy:
                return "global proxy mode"
            case .rule:
                return "rule-based proxy mode"
        }
    }
}
