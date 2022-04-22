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

public protocol HTTPProxyConfigurationProtocol {

    var username: String? { get set }

    var password: String? { get set }

    var prefererHttpTunneling: Bool { get set }
}

extension HTTPProxyConfigurationProtocol {

    var authorization: BasicAuthorization? {
        guard let username = username, let password = password else {
            return nil
        }
        return BasicAuthorization(username: username, password: password)
    }
}
