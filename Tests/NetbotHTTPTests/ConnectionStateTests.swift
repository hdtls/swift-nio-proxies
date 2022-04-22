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

@testable import NetbotHTTP

class ConnectionStateTests: XCTestCase {

    func testShouldThrowErrorForExecuteEvaluatingIfStateIsNotIdle() {
        var state = ConnectionState.evaluating
        XCTAssertThrowsError(try state.evaluating())

        state = .active
        XCTAssertThrowsError(try state.evaluating())

        state = .failed
        XCTAssertThrowsError(try state.evaluating())

        state = .idle
        XCTAssertNoThrow(try state.evaluating())
        XCTAssertEqual(state, .evaluating)
    }

    func testStateShouldBeEvaluatingAfterPerformEvaluating() {
        var state = ConnectionState.idle
        try! state.evaluating()

        XCTAssertEqual(state, .evaluating)
    }

    func testShouldThrowErrorForExecuteEstablishedWhenStateIsNotEvaluating() {
        var state = ConnectionState.idle
        XCTAssertThrowsError(try state.established())

        state = .active
        XCTAssertThrowsError(try state.established())

        state = .failed
        XCTAssertThrowsError(try state.established())

        state = .evaluating
        XCTAssertNoThrow(try state.established())
    }

    func testStateShouldBeActiveAfterPerformEstablished() {
        var state = ConnectionState.evaluating
        try! state.established()
        XCTAssertEqual(state, .active)
    }
}
