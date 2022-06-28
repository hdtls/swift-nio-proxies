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
import NetbotCore

/// A type-erased policy value.
public struct AnyPolicy {

    /// Identifier for this policy.
    public var id: UUID = .init()

    /// The actual policy value.
    public internal(set) var base: Policy

    /// Initialize an instance of `AnyPolicy` with specified base value.
    public init<P>(_ base: P) where P: Policy {
        self.base = base
    }

    public init<P>(id: UUID = .init(), base: P) where P: Policy {
        self.id = id
        self.base = base
    }
}

extension AnyPolicy {

    /// Builtin policies.
    ///
    /// For current version this array contains three element `DirectPolicy`, `RejectPolicy` and `RejectTinyGifPolicy`.
    public static let builtin: [AnyPolicy] = [
        .init(DirectPolicy()),
        .init(RejectPolicy()),
        .init(RejectTinyGifPolicy()),
    ]
}

extension AnyPolicy: Codable {

    enum CodingKeys: String, CodingKey {
        case name
        case type
        case configuration
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        let name = try container.decode(String.self, forKey: .name)

        let rawValue = try container.decode(String.self, forKey: .type)

        switch rawValue {
            case "direct":
                base = DirectPolicy()
            case "reject":
                base = RejectPolicy()
            case "reject-tinygif":
                base = RejectTinyGifPolicy()
            default:
                let proxy = try container.decode(Proxy.self, forKey: .configuration)
                base = ProxyPolicy(name: name, proxy: proxy)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)

        try container.encode(base.name, forKey: .name)

        switch base {
            case is DirectPolicy:
                try container.encode("direct", forKey: .type)
            case is RejectPolicy:
                try container.encode("reject", forKey: .type)
            case is RejectTinyGifPolicy:
                try container.encode("reject-tinygif", forKey: .type)
            case let policy as ProxyPolicy:
                try container.encodeIfPresent(policy.proxy, forKey: .configuration)
            default:
                fatalError("Unsupported policy \(base).")
        }
    }
}
