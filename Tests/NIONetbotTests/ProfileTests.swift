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

import XCTest

@testable import NIONetbot

final class ProfileTests: XCTestCase {

    let generalString = """
        [General]
        log-level = trace
        dns-servers = 223.5.5.5, 114.114.114.114, system
        exceptions = localhost, *.local, 255.255.255.255/32
        http-listen-address = 127.0.0.1
        socks-listen-address = 127.0.0.1
        socks-listen-port = 6153
        http-listen-port = 6152
        exclude-simple-hostnames = true
        """

    let replicaString = """
        [Replica]
        hide-apple-requests = true
        hide-crashlytics-requests = true
        hide-udp = true
        req-msg-filter-type = none
        req-msg-filter = google.com
        hide-crash-reporter-request = true
        """

    let policiesString = """
        [Proxy Policy]
        HTTP = http, server-address=127.0.0.1, port=8310
        HTTP BASIC = http, server-address=127.0.0.1, port=8311, username=Netbot, password=password
        SOCKS = socks5, server-address=127.0.0.1, port=8320, username=Netbot, password=password
        SHADOWSOCKS = ss, server-address=127.0.0.1, port=8330, algorithm=chacha20-poly1305, password=password, allow-udp-relay=true, tfo=true
        VMESS = vmess, server-address=127.0.0.1, port=8390, username=2EB5690D-225B-4B49-997F-697D5A36CD9D, tls=false, ws=false, ws-path=/tunnel, tfo=true
        """

    let policyGroupsString = """
        [Policy Group]
        PROXY = HTTP
        BLOCK = DIRECT, REJECT, REJECT-TINYGIF
        """

    let ruleString = """
        [Rule]
        DOMAIN-SUFFIX,icloud.com,DIRECT
        RULE-SET,SYSTEM,DIRECT
        GEOIP,CN,DIRECT
        FINAL,PROXY
        """

    let mitmString = """
        [MitM]
        skip-certificate-verification = true
        hostnames = *.google.com, *.ietf.org
        passphrase = CS2UNBDR
        base64-encoded-p12-string = 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
        """

    lazy var jsonDecoder: JSONDecoder = {
        let jsonDecoder = JSONDecoder()
        jsonDecoder.keyDecodingStrategy = .convertFromSnakeCase
        return jsonDecoder
    }()

    func testGeneralDecoding() throws {
        let jsonObject = try ProfileSerialization.jsonObject(
            with: generalString.data(using: .utf8)!
        )
        let profle = try jsonDecoder.decode(
            Profile.self,
            from: JSONSerialization.data(withJSONObject: jsonObject, options: .fragmentsAllowed)
        )

        let result = profle.general

        XCTAssertEqual(result.logLevel, .trace)
        XCTAssertEqual(result.dnsServers, ["223.5.5.5", "114.114.114.114", "system"])
        XCTAssertEqual(result.exceptions, ["localhost", "*.local", "255.255.255.255/32"])
        XCTAssertEqual(result.httpListenAddress, "127.0.0.1")
        XCTAssertEqual(result.httpListenPort, 6152)
        XCTAssertEqual(result.socksListenAddress, "127.0.0.1")
        XCTAssertEqual(result.socksListenPort, 6153)
        XCTAssertTrue(result.excludeSimpleHostnames)
    }

    func testPoliciesDecoding() throws {
        let jsonObject = try ProfileSerialization.jsonObject(
            with: policiesString.data(using: .utf8)!
        )
        let profile = try jsonDecoder.decode(
            Profile.self,
            from: JSONSerialization.data(withJSONObject: jsonObject, options: .fragmentsAllowed)
        )

        let result = profile.policies
        XCTAssertEqual(result.count, 5)
    }

    func testHTTPProxyPolicySerializationAndDecoding() throws {
        let policiesString = """
            [Proxy Policy]
            HTTP = http, server-address=127.0.0.1, port=8310, username=username, password=password, preferer-http-tunneling=true
            """
        let jsonObject = try ProfileSerialization.jsonObject(
            with: policiesString.data(using: .utf8)!
        )
        let profile = try jsonDecoder.decode(
            Profile.self,
            from: JSONSerialization.data(withJSONObject: jsonObject, options: .fragmentsAllowed)
        )

        XCTAssertFalse(profile.policies.isEmpty)
        let policy = profile.policies.first!
        guard let policy = policy as? ProxyPolicy else {
            XCTFail("should decoded as http proxy policy.")
            return
        }

        XCTAssertEqual(policy.proxy.serverAddress, "127.0.0.1")
        XCTAssertEqual(policy.proxy.port, 8310)
        XCTAssertEqual(policy.proxy.username, "username")
        XCTAssertEqual(policy.proxy.password, "password")
        XCTAssertTrue(policy.proxy.prefererHttpTunneling)
        XCTAssertEqual(policy.proxy.protocol, .http)
        XCTAssertEqual(policy.name, "HTTP")
        XCTAssertNil(policy.destinationAddress)
    }

    func testHTTPProxyPolicyDefaultValueSerializationAndDecoding() throws {
        let policiesString = """
            [Proxy Policy]
            HTTP = http, server-address=127.0.0.1, port=8310
            """
        let jsonObject = try ProfileSerialization.jsonObject(
            with: policiesString.data(using: .utf8)!
        )
        let profile = try jsonDecoder.decode(
            Profile.self,
            from: JSONSerialization.data(withJSONObject: jsonObject, options: .fragmentsAllowed)
        )

        XCTAssertFalse(profile.policies.isEmpty)
        let policy = profile.policies.first!

        guard let policy = policy as? ProxyPolicy else {
            XCTFail("should decoded as http proxy policy.")
            return
        }

        XCTAssertFalse(policy.proxy.prefererHttpTunneling)
    }

    func testHTTPSProxyPolicySerializationAndDecoding() throws {
        let policiesString = """
            [Proxy Policy]
            HTTPS = http, server-address=127.0.0.1, port=8310, username=username, password=password, sni=sni, preferer-http-tunneling=true, skip-certificate-verification=true, over-tls=true
            """
        let jsonObject = try ProfileSerialization.jsonObject(
            with: policiesString.data(using: .utf8)!
        )
        let profile = try jsonDecoder.decode(
            Profile.self,
            from: JSONSerialization.data(withJSONObject: jsonObject)
        )

        XCTAssertFalse(profile.policies.isEmpty)
        let policy = profile.policies.first!

        guard let policy = policy as? ProxyPolicy else {
            XCTFail("should decoded as http proxy policy.")
            return
        }

        XCTAssertEqual(policy.proxy.serverAddress, "127.0.0.1")
        XCTAssertEqual(policy.proxy.port, 8310)
        XCTAssertEqual(policy.proxy.username, "username")
        XCTAssertEqual(policy.proxy.password, "password")
        XCTAssertEqual(policy.proxy.sni, "sni")
        XCTAssertTrue(policy.proxy.prefererHttpTunneling)
        XCTAssertTrue(policy.proxy.skipCertificateVerification)
        XCTAssertTrue(policy.proxy.overTls)
        XCTAssertEqual(policy.proxy.protocol, .http)
        XCTAssertEqual(policy.name, "HTTPS")
        XCTAssertNil(policy.destinationAddress)
    }

    func testHTTPSProxyPolicyDefaultValueSerializationAndDecoding() throws {
        let policiesString = """
            [Proxy Policy]
            HTTPS = http, server-address=127.0.0.1, port=8310, over-tls=true
            """
        let jsonObject = try ProfileSerialization.jsonObject(
            with: policiesString.data(using: .utf8)!
        )
        let profile = try jsonDecoder.decode(
            Profile.self,
            from: JSONSerialization.data(withJSONObject: jsonObject)
        )

        XCTAssertFalse(profile.policies.isEmpty)
        let policy = profile.policies.first!

        guard let policy = policy as? ProxyPolicy else {
            XCTFail("should decoded as http proxy policy.")
            return
        }

        XCTAssertFalse(policy.proxy.prefererHttpTunneling)
        XCTAssertFalse(policy.proxy.skipCertificateVerification)
    }

    func testSOCKS5PolicySerializationAndDecoding() throws {
        let policiesString = """
            [Proxy Policy]
            SOCKS5 = socks5, server-address=127.0.0.1, port=8310, username=username, password=password
            """
        let jsonObject = try ProfileSerialization.jsonObject(
            with: policiesString.data(using: .utf8)!
        )
        let profile = try jsonDecoder.decode(
            Profile.self,
            from: JSONSerialization.data(withJSONObject: jsonObject)
        )

        XCTAssertFalse(profile.policies.isEmpty)
        let policy = profile.policies.first!

        guard let policy = policy as? ProxyPolicy else {
            XCTFail("should decoded as SOCKS5 proxy policy.")
            return
        }

        XCTAssertEqual(policy.proxy.serverAddress, "127.0.0.1")
        XCTAssertEqual(policy.proxy.port, 8310)
        XCTAssertEqual(policy.proxy.username, "username")
        XCTAssertEqual(policy.proxy.password, "password")
        XCTAssertEqual(policy.proxy.protocol, .socks5)
        XCTAssertEqual(policy.name, "SOCKS5")
        XCTAssertNil(policy.destinationAddress)
    }

    func testSOCKS5OverTLSPolicySerializationAndDecoding() throws {
        let policiesString = """
            [Proxy Policy]
            SOCKS5OverTLS = socks5, server-address=127.0.0.1, port=8310, username=username, password=password, sni=sni, skip-certificate-verification=true, over-tls=true
            """
        let jsonObject = try ProfileSerialization.jsonObject(
            with: policiesString.data(using: .utf8)!
        )
        let profile = try jsonDecoder.decode(
            Profile.self,
            from: JSONSerialization.data(withJSONObject: jsonObject)
        )

        XCTAssertFalse(profile.policies.isEmpty)
        let policy = profile.policies.first!

        guard let policy = policy as? ProxyPolicy else {
            XCTFail("should decoded as SOCKS5 over TLS proxy policy.")
            return
        }

        XCTAssertEqual(policy.proxy.serverAddress, "127.0.0.1")
        XCTAssertEqual(policy.proxy.port, 8310)
        XCTAssertEqual(policy.proxy.username, "username")
        XCTAssertEqual(policy.proxy.password, "password")
        XCTAssertEqual(policy.name, "SOCKS5OverTLS")
        XCTAssertEqual(policy.proxy.sni, "sni")
        XCTAssertEqual(policy.proxy.protocol, .socks5)
        XCTAssertTrue(policy.proxy.skipCertificateVerification)
        XCTAssertTrue(policy.proxy.overTls)
        XCTAssertNil(policy.destinationAddress)
    }

    func testSOCKS5OverTLSPolicyDefaultValueSerializationAndDecoding() throws {
        let policiesString = """
            [Proxy Policy]
            SOCKS5OverTLS = socks5, server-address=127.0.0.1, port=8310, over-tls=true
            """
        let jsonObject = try ProfileSerialization.jsonObject(
            with: policiesString.data(using: .utf8)!
        )
        let profile = try jsonDecoder.decode(
            Profile.self,
            from: JSONSerialization.data(withJSONObject: jsonObject)
        )

        XCTAssertFalse(profile.policies.isEmpty)
        let policy = profile.policies.first!

        guard let policy = policy as? ProxyPolicy else {
            XCTFail("should decoded as SOCKS5 over TLS proxy policy.")
            return
        }

        XCTAssertFalse(policy.proxy.skipCertificateVerification)
    }

    func testShadowsocksPolicySerilizationAndDecoding() throws {
        let policiesString = """
            [Proxy Policy]
            SHADOWSOCKS = ss, server-address=127.0.0.1, port=8310, algorithm=aes-128-gcm, password=password, enable-udp-relay=true, enable-tfo=true
            """
        let jsonObject = try ProfileSerialization.jsonObject(
            with: policiesString.data(using: .utf8)!
        )
        let profile = try jsonDecoder.decode(
            Profile.self,
            from: JSONSerialization.data(withJSONObject: jsonObject)
        )

        XCTAssertFalse(profile.policies.isEmpty)
        let policy = profile.policies.first!

        guard let policy = policy as? ProxyPolicy else {
            XCTFail("should decoded as shadowsocks proxy policy.")
            return
        }

        XCTAssertEqual(policy.proxy.serverAddress, "127.0.0.1")
        XCTAssertEqual(policy.proxy.port, 8310)
        XCTAssertEqual(policy.proxy.passwordReference, "password")
        XCTAssertEqual(policy.name, "SHADOWSOCKS")
        XCTAssertEqual(policy.proxy.protocol, .shadowsocks)
        XCTAssertEqual(policy.proxy.algorithm, .aes128Gcm)
        XCTAssertNil(policy.destinationAddress)
    }

    func testShadowsocksPolicyDefualtValueSerilizationAndDecoding() throws {
        let policiesString = """
            [Proxy Policy]
            SHADOWSOCKS = ss, server-address=127.0.0.1, port=8310, algorithm=aes-128-gcm, password=password
            """
        let jsonObject = try ProfileSerialization.jsonObject(
            with: policiesString.data(using: .utf8)!
        )
        let profile = try jsonDecoder.decode(
            Profile.self,
            from: JSONSerialization.data(withJSONObject: jsonObject)
        )

        XCTAssertFalse(profile.policies.isEmpty)
        let policy = profile.policies.first!

        guard let _ = policy as? ProxyPolicy else {
            XCTFail("should decoded as shadowsocks proxy policy.")
            return
        }
    }

    func testVMESSPolicySerilizationAndDecoding() throws {
        let uuid = UUID()
        let policiesString = """
            [Proxy Policy]
            VMESS = vmess, server-address=127.0.0.1, port=8310, username=\(uuid)
            """
        let jsonObject = try ProfileSerialization.jsonObject(
            with: policiesString.data(using: .utf8)!
        )
        let profile = try jsonDecoder.decode(
            Profile.self,
            from: JSONSerialization.data(withJSONObject: jsonObject)
        )

        XCTAssertFalse(profile.policies.isEmpty)
        let policy = profile.policies.first!

        guard let policy = policy as? ProxyPolicy else {
            XCTFail("should decoded as VMESS proxy policy.")
            return
        }
        XCTAssertEqual(policy.proxy.serverAddress, "127.0.0.1")
        XCTAssertEqual(policy.proxy.port, 8310)
        XCTAssertEqual(policy.proxy.username, uuid.uuidString)
        XCTAssertEqual(policy.proxy.protocol, .vmess)
        XCTAssertEqual(policy.name, "VMESS")
        XCTAssertNil(policy.destinationAddress)
    }

    func testUnsupportedPoliciesDecoding() throws {
        let policiesString = """
            [Proxy Policy]
            HTTP = IKEv2, server-address=127.0.0.1, port=8310
            """
        let jsonObject = try ProfileSerialization.jsonObject(
            with: policiesString.data(using: .utf8)!
        )

        XCTAssertThrowsError(
            try jsonDecoder.decode(
                Profile.self,
                from: JSONSerialization.data(withJSONObject: jsonObject, options: .fragmentsAllowed)
            )
        )
    }

    func testPolicyGroupsDecoding() throws {
        let policyGroupsString = [self.policiesString, self.policyGroupsString].joined(
            separator: "\n"
        )
        let jsonObject = try ProfileSerialization.jsonObject(
            with: policyGroupsString.data(using: .utf8)!
        )
        let profile = try jsonDecoder.decode(
            Profile.self,
            from: JSONSerialization.data(withJSONObject: jsonObject, options: .fragmentsAllowed)
        )

        let result = profile.policyGroups
        XCTAssertEqual(result.count, 2)
        XCTAssertEqual(result.first?.name, "PROXY")
        XCTAssertEqual(result.first?.policies.count, 1)
        XCTAssertTrue(result.first!.policies.contains(where: { $0.name == "HTTP" }))
        XCTAssertEqual(result.last?.name, "BLOCK")
        XCTAssertEqual(result.last?.policies.count, 3)
    }

    func testDecodingPolicyGroupsWhichContainsPoliciesNoDefinedInPolicies() {
        XCTAssertThrowsError(
            try ProfileSerialization.jsonObject(with: policyGroupsString.data(using: .utf8)!)
        ) { error in
            XCTAssertTrue(error is ProfileSerializationError)

            let err = error as! ProfileSerializationError

            guard case .invalidFile(let reason) = err,
                case .unknownPolicy(cursor: let cursor, policy: let policy) = reason
            else {
                XCTFail()
                return
            }

            XCTAssertEqual(cursor, 2)
            XCTAssertEqual(policy, "HTTP")
        }
    }

    func testRuleDecoding() throws {
        let ruleString = [self.policiesString, self.policyGroupsString, self.ruleString].joined(
            separator: "\n"
        )
        let jsonObject = try ProfileSerialization.jsonObject(
            with: ruleString.data(using: .utf8)!
        )
        let profile = try jsonDecoder.decode(
            Profile.self,
            from: JSONSerialization.data(withJSONObject: jsonObject, options: .fragmentsAllowed)
        )

        let result = profile.rules
        XCTAssertEqual(result.count, 4)

        XCTAssertTrue(result.first?.type == .domainSuffix)
        XCTAssertTrue(result[1].type == .ruleSet)
        XCTAssertTrue(result[2].type == .geoIp)
        XCTAssertTrue(result[3].type == .final)
    }

    func testMitMDecoding() throws {
        let jsonObject = try ProfileSerialization.jsonObject(
            with: mitmString.data(using: .utf8)!
        )
        let profile = try jsonDecoder.decode(
            Profile.self,
            from: JSONSerialization.data(withJSONObject: jsonObject, options: .fragmentsAllowed)
        )

        let result = profile.mitm

        XCTAssertTrue(result.skipCertificateVerification)
        XCTAssertEqual(result.hostnames, ["*.google.com", "*.ietf.org"])
        XCTAssertEqual(result.passphrase, "CS2UNBDR")
        XCTAssertEqual(
            result.base64EncodedP12String,
            "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"
        )
    }
}
