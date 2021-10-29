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

import XCTest
@testable import Netbot

final class ConfigurationParserTests: XCTestCase {
    
    func testReplicaEncoding() throws {
        let expect = ReplicaConfiguration(hideAppleRequests: true, hideCrashlyticsRequests: false, hideCrashReporterRequests: true, hideUDP: true, reqMsgFilterType: .none, reqMsgFilter: "github.com")
        
        let data = try JSONEncoder().encode(expect)
        let result = try JSONDecoder().decode(ReplicaConfiguration.self, from: data)
        
        XCTAssertEqual(result, expect)
    }
}
