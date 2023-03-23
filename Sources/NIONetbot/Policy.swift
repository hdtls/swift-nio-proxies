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

import ConnectionPool
import Foundation
import NIONetbotMisc

/// Policy protocol representation a policy object.
public protocol Policy: ConnectionPoolSource, Sendable {

    /// The name of the policy.
    var name: String { get set }

    /// Destination address.
    var destinationAddress: NetAddress? { get set }
}

/// DirectPolicy will tunnel connection derectly.
public struct DirectPolicy: Policy {

    public var name: String

    public var destinationAddress: NetAddress?

    public init(name: String = "DIRECT", destinationAddress: NetAddress? = nil) {
        self.name = name
        self.destinationAddress = destinationAddress
    }
}

/// RejectPolicy will reject connection to the destination.
public struct RejectPolicy: Policy {

    public var name: String

    public var destinationAddress: NetAddress?

    public init(name: String = "REJECT", destinationAddress: NetAddress? = nil) {
        self.name = name
        self.destinationAddress = destinationAddress
    }
}

/// RejectTinyGifPolicy will reject connection and response a tiny gif.
public struct RejectTinyGifPolicy: Policy {

    public var name: String

    public var destinationAddress: NetAddress?

    public init(
        name: String = "REJECT-TINYGIF",
        destinationAddress: NetAddress? = nil
    ) {
        self.name = name
        self.destinationAddress = destinationAddress
    }
}

public struct ProxyPolicy: Policy {

    public var name: String

    public var proxy: Proxy

    public var destinationAddress: NetAddress?

    public init(
        name: String,
        proxy: Proxy,
        destinationAddress: NetAddress? = nil
    ) {
        self.name = name
        self.proxy = proxy
        self.destinationAddress = destinationAddress
    }
}

public enum Builtin: Sendable {

    public static let policies: [any Policy] = [
        DirectPolicy(),
        RejectPolicy(),
        RejectTinyGifPolicy(),
    ]
}
