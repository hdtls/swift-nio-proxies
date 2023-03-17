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

import Foundation
import NIOHTTP1

/// A basic username and password.
struct BasicAuthorization: Equatable {
    /// The username, sometimes an email address
    let username: String

    /// The plaintext password
    let password: String
}

extension HTTPHeaders {

    var proxyBasicAuthorization: BasicAuthorization? {
        get {
            guard let string = self.first(name: .proxyAuthorization) else {
                return nil
            }

            let headerParts = string.components(separatedBy: "Basic ")
            guard headerParts.count == 2 else {
                return nil
            }

            guard let data = Data(base64Encoded: headerParts[1]) else {
                return nil
            }

            let parts = String(decoding: data, as: UTF8.self).split(
                separator: ":",
                maxSplits: 1
            )

            guard parts.count == 2 else {
                return nil
            }

            return .init(username: .init(parts[0]), password: .init(parts[1]))
        }
        set {
            if let basic = newValue {
                let credentials = "\(basic.username):\(basic.password)"
                let encoded = Data(credentials.utf8).base64EncodedString()
                replaceOrAdd(name: .proxyAuthorization, value: "Basic \(encoded)")
            } else {
                remove(name: .proxyAuthorization)
            }
        }
    }
}
