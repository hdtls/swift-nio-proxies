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

import ConnectionPool
import Foundation
import NIOSSL
import NetbotCore
import NetbotHTTP
import NetbotSOCKS
import NetbotSS
import NetbotVMESS

/// Policy protocol representation a policy object.
public protocol Policy: ConnectionPoolSource {

    /// The name of the policy.
    var name: String { get set }

    /// Destination address.
    var destinationAddress: NetAddress? { get set }
}

/// DirectPolicy will tunnel connection derectly.
public struct DirectPolicy: Policy {

    public var name: String = "DIRECT"

    public var destinationAddress: NetAddress?

    public init() {}
}

/// RejectPolicy will reject connection to the destination.
public struct RejectPolicy: Policy {

    public var name: String = "REJECT"

    public var destinationAddress: NetAddress?

    public init() {}
}

/// RejectTinyGifPolicy will reject connection and response a tiny gif.
public struct RejectTinyGifPolicy: Policy {

    public var name: String = "REJECT-TINYGIF"

    public var destinationAddress: NetAddress?

    public init() {}
}

public struct ProxyPolicy: Policy {

    public var name: String

    public var proxy: Proxy

    public var destinationAddress: NetAddress?

    public init(name: String, proxy: Proxy, destinationAddress: NetAddress? = nil) {
        self.name = name
        self.proxy = proxy
        self.destinationAddress = destinationAddress
    }
}
