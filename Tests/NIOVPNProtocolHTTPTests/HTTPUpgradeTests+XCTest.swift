//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright © 2019 Netbot Ltd. and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import XCTest

extension NIOVPNProtocolHTTPTests {
    static var allTests = [
        ("testUpgradeWithoutSendHttpEndPart", testUpgradeWithoutSendHttpEndPart),
        ("testUpgradeHandlerBufferOnUnexpectedOrdering", testUpgradeHandlerBufferOnUnexpectedOrdering),
        ("testUpgradeWhenBuildProxyResponseFailed", testUpgradeWhenBuildProxyResponseFailed),
        ("testUpgradeFiresUserEvent", testUpgradeFiresUserEvent)
    ]
}
