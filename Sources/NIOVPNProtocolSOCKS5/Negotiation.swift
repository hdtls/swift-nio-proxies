//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright © 2019 Netbot Ltd. All rights reserved. and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation
import NIO

public enum Negotiation {

    public enum AuthNegotiation {
        case basicAuth(Any)
    }

    case hello(Any)
    case authentication(AuthNegotiation)
    case replies(Any)
    case completion(ByteBuffer)
}
