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

import NIONetbot

/// Policy coding wrapper.
struct __Policy {

    /// The actual policy value.
    var base: any NIONetbot.Policy

    /// Initialize an instance of `__Policy` with specified base value.
    init(_ base: any NIONetbot.Policy) {
        self.base = base
    }
}

extension __Policy: Codable {

    enum CodingKeys: String, CodingKey {
        case name
        case type
        case proxy
    }

    init(from decoder: Decoder) throws {
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
                let proxy = try container.decode(Proxy.self, forKey: .proxy)
                base = ProxyPolicy(name: name, proxy: proxy)
        }
    }

    func encode(to encoder: Encoder) throws {
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
                try container.encode(policy.proxy.protocol.rawValue, forKey: .type)
                try container.encodeIfPresent(policy.proxy, forKey: .proxy)
            default:
                fatalError("Unsupported policy \(base).")
        }
    }
}
