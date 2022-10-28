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

#if swift(>=5.5) && canImport(_Concurrency)
/// Policy protocol representation a policy object.
public protocol Policy: ConnectionPoolSource, Sendable {

    var id: UUID { get }

    /// The name of the policy.
    var name: String { get set }

    /// Destination address.
    var destinationAddress: NetAddress? { get set }
}
#else
/// Policy protocol representation a policy object.
public protocol Policy: ConnectionPoolSource {

    var id: UUID { get }

    /// The name of the policy.
    var name: String { get set }

    /// Destination address.
    var destinationAddress: NetAddress? { get set }
}
#endif

/// DirectPolicy will tunnel connection derectly.
public struct DirectPolicy: Policy {

    public var id: UUID

    public var name: String

    public var destinationAddress: NetAddress?

    public init(id: UUID = .init(), name: String = "DIRECT", destinationAddress: NetAddress? = nil)
    {
        self.id = id
        self.name = name
        self.destinationAddress = destinationAddress
    }
}

/// RejectPolicy will reject connection to the destination.
public struct RejectPolicy: Policy {

    public var id: UUID

    public var name: String

    public var destinationAddress: NetAddress?

    public init(id: UUID = .init(), name: String = "REJECT", destinationAddress: NetAddress? = nil)
    {
        self.id = id
        self.name = name
        self.destinationAddress = destinationAddress
    }
}

/// RejectTinyGifPolicy will reject connection and response a tiny gif.
public struct RejectTinyGifPolicy: Policy {

    public var id: UUID

    public var name: String

    public var destinationAddress: NetAddress?

    public init(
        id: UUID = .init(),
        name: String = "REJECT-TINYGIF",
        destinationAddress: NetAddress? = nil
    ) {
        self.id = id
        self.name = name
        self.destinationAddress = destinationAddress
    }
}

public struct ProxyPolicy: Policy {

    public var id: UUID

    public var name: String

    public var proxy: Proxy

    public var destinationAddress: NetAddress?

    public init(
        id: UUID = .init(),
        name: String,
        proxy: Proxy,
        destinationAddress: NetAddress? = nil
    ) {
        self.id = id
        self.name = name
        self.proxy = proxy
        self.destinationAddress = destinationAddress
    }
}

public enum Builtin {

    public static let policies: [any Policy] = [
        DirectPolicy(),
        RejectPolicy(),
        RejectTinyGifPolicy(),
    ]
}

#if swift(>=5.5) && canImport(_Concurrency)
extension Builtin: Sendable {}
#endif
