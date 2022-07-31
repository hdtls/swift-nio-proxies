//===----------------------------------------------------------------------===//
//
// This source file is part of the Netbot open source project
//
// Copyright (c) 2022 Junfeng Zhang. and the Netbot project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
// See CONTRIBUTORS.txt for the list of Netbot project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import XCTest

@testable import NIOHTTPMitM

final class CertificateStoreTests: XCTestCase {

    var store: CertificateStore!
    lazy var base64EncodedP12String: String = {
        let cert = CertificateAuthority(organization: "xctest", commonName: "NIOHTTMMitMTests")
        return try! cert.exportBase64EncodedP12String(passphrase: passphrase)
    }()
    let passphrase = "passphrase"

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
        try store = CertificateStore(
            passphrase: passphrase,
            base64EncodedP12String: base64EncodedP12String
        )
    }

    func testInitializeWithWrongPassphrase() {
        XCTAssertThrowsError(
            try CertificateStore(
                passphrase: "wrong passphrase",
                base64EncodedP12String: base64EncodedP12String
            )
        )
    }

    func testInitializeWithInvalidP12String() {
        XCTAssertThrowsError(
            try CertificateStore(
                passphrase: passphrase,
                base64EncodedP12String: "base64EncodedP12String"
            )
        )
    }

    func testShouldPerfomMitMIfPossible() async {
        await store.setUpMitMHosts(["*.swift.org"])
        var expression = await store.shouldPerformMitMIfPossible(for: "www.swift.org")
        XCTAssertTrue(expression)
        expression = await store.shouldPerformMitMIfPossible(for: "swift.org")
        XCTAssertFalse(expression)
        expression = await store.shouldPerformMitMIfPossible(for: "wift.org")
        XCTAssertFalse(expression)

        await store.setUpMitMHosts(["swift.org"])
        expression = await store.shouldPerformMitMIfPossible(for: "swift.org")
        XCTAssertTrue(expression)
        expression = await store.shouldPerformMitMIfPossible(for: "www.swift.org")
        XCTAssertFalse(expression)
        expression = await store.shouldPerformMitMIfPossible(for: "wift.org")
        XCTAssertFalse(expression)
    }

    func testUpdateHostsShouldAlsoUpdateCertPool() async throws {
        await store.setUpMitMHosts([])
        await store.setUpMitMHosts(["*.swift.org"])
        var pool = await store.pool
        XCTAssertTrue(pool.isEmpty)

        _ = try await store.certificate(identifiedBy: "*.swift.org")
        var hosts = await store.hostnames
        pool = await store.pool
        XCTAssertEqual(hosts, ["*.swift.org"])
        XCTAssertEqual(Array(pool.keys), ["*.swift.org"])
        XCTAssertEqual(pool.values.count, 1)

        await store.setUpMitMHosts(["*.swift.org", "swift.org"])
        _ = try await store.certificate(identifiedBy: "swift.org")
        hosts = await store.hostnames
        pool = await store.pool
        XCTAssertEqual(hosts, ["*.swift.org", "swift.org"])
        XCTAssertEqual(pool.keys.count, 2)
        XCTAssertEqual(pool.values.count, 2)

        await store.setUpMitMHosts(["*.swift.org"])
        hosts = await store.hostnames
        pool = await store.pool
        XCTAssertEqual(hosts, ["*.swift.org"])
        XCTAssertEqual(Array(pool.keys), ["*.swift.org"])
        XCTAssertEqual(pool.values.count, 1)

        await store.setUpMitMHosts([])
        hosts = await store.hostnames
        pool = await store.pool
        XCTAssertTrue(hosts.isEmpty)
        XCTAssertTrue(pool.isEmpty)
    }

    func testFindCertWithServerHostname() async throws {
        await store.setUpMitMHosts([])
        var should = await store.shouldPerformMitMIfPossible(for: "swift.org")
        XCTAssertFalse(should)
        var p12 = try await store.certificate(identifiedBy: "swift.org")
        XCTAssertNil(p12)

        await store.setUpMitMHosts(["swift.org"])
        should = await store.shouldPerformMitMIfPossible(for: "swift.org")
        XCTAssertTrue(should)
        p12 = try await store.certificate(identifiedBy: "swift.org")
        XCTAssertNotNil(p12)

        should = await store.shouldPerformMitMIfPossible(for: "*.swift.org")
        XCTAssertFalse(should)
        p12 = try await store.certificate(identifiedBy: "*.swift.org")
        XCTAssertNil(p12)
    }
}
